<?php

namespace Dlongopinc\SecurityAnalyzer;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

class SecurityAnalyzer
{
    /**
     * Analyzes a directory for all PHP files.
     *
     * @param string $dir The directory to analyze.
     * @return array An array of file paths.
     */
    public function analyzePhpFiles(string $dir): array
    {
        $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
        $files = [];

        foreach ($rii as $file) {
            if ($file->isDir()) {
                continue;
            }
            if (pathinfo($file->getPathname(), PATHINFO_EXTENSION) === 'php') {
                $files[] = $file->getPathname();
            }
        }
        return $files;
    }

    /**
     * Checks a single PHP file for potential XSS vulnerabilities.
     *
     * @param string $file The path to the PHP file.
     * @return array An array of found issues with details.
     */
    public function checkFile(string $file): array
    {
        $content = file_get_contents($file);
        if ($content === false) {
            return [];
        }

        $lines = explode("\n", $content);
        $issues = [];
        $inputVars = [];

        // --- Step 1: Detect candidate variables from superglobals & foreach ---
        foreach ($lines as $num => $lineRaw) {
            $line = trim($lineRaw);
            if (preg_match('/^\s*(\/\/|#|\/\*|\*|\*\/|<)/', $line)) continue;

            if (preg_match('/\$(\w+)\s*=\s*\$_(POST|GET|REQUEST|COOKIE|SESSION)\b/', $line, $m)) {
                $inputVars[$m[1]] = ["line" => $num + 1, "secured" => false];
            }

            if (preg_match('/\bforeach\s*\([^)]*\s+as\s+\$(\w+)(?:\s*=>\s*\$(\w+))?/', $line, $m)) {
                if (!empty($m[1]) && !isset($inputVars[$m[1]])) {
                    $inputVars[$m[1]] = ["line" => $num + 1, "secured" => false];
                }
                if (!empty($m[2]) && !isset($inputVars[$m[2]])) {
                    $inputVars[$m[2]] = ["line" => $num + 1, "secured" => false];
                }
            }
        }

        // --- Integrate AST-based findings (PhpParser) to improve type heuristics ---
        // If PhpParserAnalyzer is available, use it to mark variables that are arrays
        try {
            $parserAnalyzer = new PhpParserAnalyzer();
            $astFindings = $parserAnalyzer->analyzeFile($file);
            foreach ($astFindings as $f) {
                if (!empty($f['error'])) continue;
                if (empty($f['name'])) continue;
                $name = $f['name'];
                if (!isset($inputVars[$name])) {
                    $inputVars[$name] = ["line" => $f['line'] ?? 0, "secured" => false];
                }
                if (!empty($f['is_array'])) {
                    $inputVars[$name]['is_array'] = true;
                    $inputVars[$name]['reasons'] = $f['reasons'] ?? [];
                } else {
                    // ensure key exists
                    if (!isset($inputVars[$name]['is_array'])) {
                        $inputVars[$name]['is_array'] = false;
                    }
                }
                // if AST reports is_array via is_array() check, prefer that
                if (!empty($f['reasons']) && in_array('checked with is_array()', $f['reasons'])) {
                    $inputVars[$name]['is_array'] = true;
                }
            }
        } catch (\Throwable $e) {
            // fall back to original heuristics if parser fails or not installed
        }

        // --- Step 2: Mark as "secured" if the variable is assigned from htmlspecialchars(...) ---
        foreach ($lines as $num => $lineRaw) {
            $line = trim($lineRaw);
            if (preg_match('/^\s*(\/\/|#|\/\*|\*|\*\/|<)/', $line)) continue;

            foreach ($inputVars as $var => &$info) {
                $v = preg_quote($var, '/');
                if (preg_match('/^\s*\$(' . $v . ')\b\s*=\s*htmlspecialchars\s*\(/', $line)) {
                    $info["secured"] = true;
                }
            }
            unset($info);
        }

        // --- Step 3: Analyze usage and generate fix suggestions ---
        foreach ($lines as $num => $lineRaw) {
            $line = trim($lineRaw);
            if (preg_match('/^\s*(\/\/|#|\/\*|\*|\*\/|<)/', $line)) continue;

            if (preg_match('/\barray_keys\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SESSION)\b/', $line)) {
                continue;
            }

            foreach ($inputVars as $var => $info) {
                if (strpos($line, '$' . $var) === false) continue;
                $v = preg_quote($var, '/');

                if (preg_match('/^\s*\$(' . $v . ')\b\s*=\s*(\$_(?:POST|GET|REQUEST|COOKIE|SESSION)(?:\s*\[[^\]]+\])*)(\s*;.*)?$/', $line, $m2)) {
                    // if AST indicates this variable is an array, don't suggest wrapping whole var
                    if (!empty($info['is_array'])) {
                        continue;
                    }
                    $rhs = $m2[2];
                    $tail = isset($m2[3]) ? $m2[3] : ';';
                    $suggestedFix = '$' . $var . ' = htmlspecialchars(' . $rhs . ')' . $tail;
                    $issues[] = ["line" => $num + 1, "var" => $var, "code" => trim($line), "fix" => $suggestedFix];
                    continue;
                }

                if ($info["secured"]) continue;
                // if AST says this variable is an array, skip suggestions that would wrap the whole variable
                if (!empty($info['is_array'])) {
                    // allow suggestions for element access or implode(...) but skip plain $var usage
                    if (preg_match('/\$' . $v . '(?![\w\[]|->)/', $line)) {
                        continue;
                    }
                }
                if (preg_match('/\bforeach\s*\([^)]*\$(' . $v . ')\b/', $line)) continue;
                if (preg_match('/\barray_keys\s*\(\s*\$(' . $v . ')(?:\s*\[[^\)]*\])?\s*\)/', $line)) continue;
                if (preg_match('/\bhtmlspecialchars\s*\([^)]*\$' . $v . '[^)]*\)/', $line)) continue;

                $suggestedFix = $this->generateFixSuggestion($line, $var);
                if (trim($suggestedFix) === trim($line)) continue;

                $issues[] = ["line" => $num + 1, "var" => $var, "code" => trim($line), "fix" => $suggestedFix];
            }
        }

        return $issues;
    }

    /**
     * Generates a fix suggestion for a given line and variable.
     *
     * @param string $line The line of code.
     * @param string $var The variable name.
     * @return string The suggested fix.
     */
    private function generateFixSuggestion(string $line, string $var): string
    {
        $trimmedLine = rtrim($line);
        $v = preg_quote($var, '/');

        if (preg_match('/\bhtmlspecialchars\s*\([^)]*\$' . $v . '(?:\s*\[[^\)]*\])?/i', $trimmedLine)) {
            return $trimmedLine;
        }

        $processRhs = function ($rhs) use ($v, $var) {
            $new = $rhs;
            $new = preg_replace_callback('/implode\s*\(([^)]*\$' . $v . '[^)]*)\)/i', function ($m) {
                return 'htmlspecialchars(implode(' . $m[1] . '))';
            }, $new);
            $new = preg_replace_callback('/\$' . $v . '(?:\s*\[[^\]]+\])+/', function ($m) {
                return 'htmlspecialchars(' . $m[0] . ')';
            }, $new);
            $new = preg_replace('/\$' . $v . '(?![\w\[]|->)/', 'htmlspecialchars($' . $var . ')', $new);
            return $new;
        };

        if (preg_match('/^(.*?)\s*([+\-\*\/\.]{0,2}=)\s*(.*?)(\s*(?:;|$).*)$/', $trimmedLine, $m)) {
            $lhs = $m[1];
            $op = $m[2];
            $rhs = $m[3];
            $tail = isset($m[4]) ? $m[4] : '';
            if (preg_match('/\$' . $v . '\b/', $lhs)) {
                $newRhs = $processRhs($rhs);
                if (trim($newRhs) !== trim($rhs)) {
                    return $lhs . ' ' . $op . ' ' . $newRhs . $tail;
                }
                return $trimmedLine;
            }
            $newRhs = $processRhs($rhs);
            if (trim($newRhs) !== trim($rhs)) {
                return $lhs . ' ' . $op . ' ' . $newRhs . $tail;
            }
        }

        if (preg_match('/implode\s*\([^)]*\$' . $v . '[^)]*\)/i', $trimmedLine)) {
            $new = preg_replace_callback('/implode\s*\(([^)]*\$' . $v . '[^)]*)\)/i', function ($m) {
                return 'htmlspecialchars(implode(' . $m[1] . '))';
            }, $trimmedLine);
            if ($new !== null && $new !== $trimmedLine) return $new;
        }

        $new = preg_replace_callback('/\$' . $v . '(?:\s*\[[^\]]+\])+/', function ($m) {
            return 'htmlspecialchars(' . $m[0] . ')';
        }, $trimmedLine);
        if ($new !== null && $new !== $trimmedLine) return $new;

        if (preg_match('/^\s*echo\s+(.*)$/', $trimmedLine, $matches)) {
            $content = $matches[1];
            $fixedContent = preg_replace('/\$' . $v . '(?![\w\[]|->)/', 'htmlspecialchars($' . $var . ')', $content);
            return "echo " . $fixedContent;
        }

        if (preg_match('/^\s*print\s+(.*)$/', $trimmedLine, $matches)) {
            $content = $matches[1];
            $fixedContent = preg_replace('/\$' . $v . '(?![\w\[]|->)/', 'htmlspecialchars($' . $var . ')', $content);
            return "print " . $fixedContent;
        }

        if (preg_match('/=\s*["\'].*\$' . $v . '.*["\']/', $trimmedLine)) {
            return preg_replace('/\$' . $v . '(?!\w)/', '" . htmlspecialchars($' . $var . ') . "', $trimmedLine);
        }

        if (preg_match('/\b(value|placeholder|title)\s*=\s*["\'][^"\']*\$' . $v . '[^"\']*["\']/', $trimmedLine)) {
            return preg_replace('/\$' . $v . '(?!\w)/', '" . htmlspecialchars($' . $var . ') . "', $trimmedLine);
        }

        $newLine = preg_replace('/\$' . $v . '(?![\w\[]|->)/', 'htmlspecialchars($' . $var . ')', $trimmedLine);

        return ($newLine === null) ? $trimmedLine : $newLine;
    }
}
