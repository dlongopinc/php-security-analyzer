<?php

namespace Dlongopinc\SecurityAnalyzer;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;
use PhpParser\NodeTraverser;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard as PrettyPrinter;

/**
 * Simple wrapper around nikic/php-parser to detect variable assignments and
 * whether a variable is likely an array or scalar based on AST patterns.
 */
class PhpParserAnalyzer
{
    /**
     * Parse PHP code and return findings: [ [name, line, is_array, reason], ... ]
     *
     * @param string $code PHP source code
     * @return array
     */
    public function analyzeCode(string $code): array
    {
        $parser = (new ParserFactory())->create(ParserFactory::PREFER_PHP7);
        $traverser = new NodeTraverser();
        $printer = new PrettyPrinter();

        $visitor = new class($printer) extends NodeVisitorAbstract {
            private $printer;
            public $findings = [];

            public function __construct(PrettyPrinter $printer)
            {
                $this->printer = $printer;
            }

            public function enterNode(Node $node)
            {
                // Detect assignments $var = ...;
                if ($node instanceof Node\Expr\Assign) {
                    $var = $node->var;
                    $expr = $node->expr;

                    if ($var instanceof Node\Expr\Variable && is_string($var->name)) {
                        $name = $var->name;
                        $isArray = false;
                        $reason = [];

                        // Array literal: [ ... ] or array(...)
                        if ($expr instanceof Node\Expr\Array_) {
                            $isArray = true;
                            $reason[] = 'array literal';
                        }

                        // Assigned from superglobal variable: $_POST, $_GET, etc.
                        if ($expr instanceof Node\Expr\Variable && is_string($expr->name) && in_array($expr->name, ['_POST','_GET','_REQUEST','_COOKIE','_SESSION'])) {
                            $isArray = true;
                            $reason[] = 'assigned from superglobal';
                        }

                        // Assigned from superglobal element: $_POST['x'] -> not a whole array
                        if ($expr instanceof Node\Expr\ArrayDimFetch && $expr->var instanceof Node\Expr\Variable && is_string($expr->var->name) && in_array($expr->var->name, ['_POST','_GET','_REQUEST','_COOKIE','_SESSION'])) {
                            $isArray = false;
                            $reason[] = 'assigned from superglobal element';
                        }

                        // Assigned from function call that obviously returns array: array_keys(), array_map(), etc.
                        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
                            $fname = strtolower($expr->name->toString());
                            $arrayFuncs = ['array_keys','array_values','array_map','array_filter','explode','preg_split','range','glob'];
                            if (in_array($fname, $arrayFuncs)) {
                                $isArray = true;
                                $reason[] = 'assigned from ' . $fname . '()';
                            }
                        }

                        // If right-hand side is new \ SomeClass() and it's annotated or known - skip (unknown)

                        $this->findings[] = [
                            'name' => $name,
                            'line' => $node->getLine(),
                            'is_array' => $isArray,
                            'reasons' => $reason,
                            'code' => $this->printer->prettyPrintExpr($expr),
                        ];
                    }
                }

                // Detect foreach($arr as $it)
                if ($node instanceof Node\Stmt\Foreach_) {
                    $expr = $node->expr;
                    if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
                        $this->findings[] = [
                            'name' => $expr->name,
                            'line' => $node->getLine(),
                            'is_array' => true,
                            'reasons' => ['used in foreach'],
                            'code' => $this->printer->prettyPrintExpr($expr),
                        ];
                    }
                }

                // Detect calls to is_array($var)
                if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name && strtolower($node->name->toString()) === 'is_array') {
                    if (!empty($node->args)) {
                        $argVal = $node->args[0]->value;
                        if ($argVal instanceof Node\Expr\Variable && is_string($argVal->name)) {
                            $this->findings[] = [
                                'name' => $argVal->name,
                                'line' => $node->getLine(),
                                'is_array' => true,
                                'reasons' => ['checked with is_array()'],
                                'code' => 'is_array',
                            ];
                        }
                    }
                }
            }
        };

        $traverser->addVisitor($visitor);

        try {
            $ast = $parser->parse($code);
            $traverser->traverse($ast);
            return $visitor->findings;
        } catch (Error $e) {
            return [
                ['error' => 'parse_error', 'message' => $e->getMessage()]
            ];
        }
    }

    /**
     * Convenience: analyze a file path
     * @param string $filePath
     * @return array
     */
    public function analyzeFile(string $filePath): array
    {
        if (!is_readable($filePath)) {
            return [['error' => 'unreadable_file', 'file' => $filePath]];
        }
        $code = file_get_contents($filePath);
        return $this->analyzeCode($code);
    }
}
