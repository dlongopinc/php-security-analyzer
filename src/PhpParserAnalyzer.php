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
            public $varFindings = [];
            public $calls = [];
            public $usages = []; // write-contexts and similar

            public function __construct(PrettyPrinter $printer)
            {
                $this->printer = $printer;
            }

            private function collectVarsFromExpr($expr)
            {
                $vars = [];
                if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
                    $vars[] = $expr->name;
                }
                if ($expr instanceof Node\Expr\ArrayDimFetch) {
                    $vars = array_merge($vars, $this->collectVarsFromExpr($expr->var));
                    if ($expr->dim !== null) {
                        $vars = array_merge($vars, $this->collectVarsFromExpr($expr->dim));
                    }
                }
                if ($expr instanceof Node\Expr\PropertyFetch) {
                    // $obj->prop — treat as variable usage of the property root if variable
                    $vars = array_merge($vars, $this->collectVarsFromExpr($expr->var));
                }
                if ($expr instanceof Node\Expr\FuncCall || $expr instanceof Node\Expr\MethodCall || $expr instanceof Node\Expr\StaticCall) {
                    // examine args
                    foreach ($expr->args as $a) {
                        $vars = array_merge($vars, $this->collectVarsFromExpr($a->value));
                    }
                }
                if ($expr instanceof Node\Expr\BinaryOp) {
                    $vars = array_merge($vars, $this->collectVarsFromExpr($expr->left));
                    $vars = array_merge($vars, $this->collectVarsFromExpr($expr->right));
                }
                if ($expr instanceof Node\Expr\Ternary) {
                    $vars = array_merge($vars, $this->collectVarsFromExpr($expr->cond));
                    if ($expr->if) $vars = array_merge($vars, $this->collectVarsFromExpr($expr->if));
                    $vars = array_merge($vars, $this->collectVarsFromExpr($expr->else));
                }
                return array_filter(array_unique($vars));
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

                        $this->varFindings[] = [
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
                        $this->varFindings[] = [
                            'name' => $expr->name,
                            'line' => $node->getLine(),
                            'is_array' => true,
                            'reasons' => ['used in foreach'],
                            'code' => $this->printer->prettyPrintExpr($expr),
                        ];
                    }
                }

                // Detect calls: function calls, method calls, static calls
                if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
                    $fname = strtolower($node->name->toString());
                    $vars = [];
                    foreach ($node->args as $a) {
                        $vars = array_merge($vars, $this->collectVarsFromExpr($a->value));
                    }
                    $this->calls[] = ['type' => 'function', 'name' => $fname, 'line' => $node->getLine(), 'args' => array_map(function($a){ return $this->printer->prettyPrintExpr($a->value); }, $node->args), 'vars' => array_values(array_unique($vars))];
                }

                if ($node instanceof Node\Expr\MethodCall) {
                    $mname = null;
                    if ($node->name instanceof Node\Identifier) $mname = $node->name->toString();
                    $vars = [];
                    foreach ($node->args as $a) {
                        $vars = array_merge($vars, $this->collectVarsFromExpr($a->value));
                    }
                    $this->calls[] = ['type' => 'method', 'name' => $mname, 'line' => $node->getLine(), 'args' => array_map(function($a){ return $this->printer->prettyPrintExpr($a->value); }, $node->args), 'vars' => array_values(array_unique($vars))];
                }

                if ($node instanceof Node\Expr\StaticCall) {
                    $mname = null;
                    if ($node->name instanceof Node\Identifier) $mname = $node->name->toString();
                    $vars = [];
                    foreach ($node->args as $a) {
                        $vars = array_merge($vars, $this->collectVarsFromExpr($a->value));
                    }
                    $this->calls[] = ['type' => 'static', 'name' => $mname, 'line' => $node->getLine(), 'args' => array_map(function($a){ return $this->printer->prettyPrintExpr($a->value); }, $node->args), 'vars' => array_values(array_unique($vars))];
                }

                // Detect calls to is_array($var)
                if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name && strtolower($node->name->toString()) === 'is_array') {
                    if (!empty($node->args)) {
                        $argVal = $node->args[0]->value;
                        if ($argVal instanceof Node\Expr\Variable && is_string($argVal->name)) {
                            $this->varFindings[] = [
                                'name' => $argVal->name,
                                'line' => $node->getLine(),
                                'is_array' => true,
                                'reasons' => ['checked with is_array()'],
                                'code' => 'is_array',
                            ];
                        }
                    }
                }

                // Detect write-contexts: isset(), empty(), unset(), inc/dec
                if ($node instanceof Node\Expr\Isset_) {
                    foreach ($node->vars as $v) {
                        $this->usages[] = ['type' => 'isset', 'line' => $node->getLine(), 'vars' => $this->collectVarsFromExpr($v)];
                    }
                }
                if ($node instanceof Node\Expr\Empty_) {
                    $this->usages[] = ['type' => 'empty', 'line' => $node->getLine(), 'vars' => $this->collectVarsFromExpr($node->expr)];
                }
                if ($node instanceof Node\Stmt\Unset_) {
                    foreach ($node->vars as $v) {
                        $this->usages[] = ['type' => 'unset', 'line' => $node->getLine(), 'vars' => $this->collectVarsFromExpr($v)];
                    }
                }
                if ($node instanceof Node\Expr\PreInc || $node instanceof Node\Expr\PostInc || $node instanceof Node\Expr\PreDec || $node instanceof Node\Expr\PostDec) {
                    $this->usages[] = ['type' => 'incdec', 'line' => $node->getLine(), 'vars' => $this->collectVarsFromExpr($node->var)];
                }
                    // Detect return statements and record returned variable(s)
                    if ($node instanceof Node\Stmt\Return_) {
                        if ($node->expr !== null) {
                            $vars = $this->collectVarsFromExpr($node->expr);
                            if (!empty($vars)) {
                                $this->usages[] = ['type' => 'return', 'line' => $node->getLine(), 'vars' => $vars];
                            }
                        }
                    }
            }
        };

        $traverser->addVisitor($visitor);

        try {
            $ast = $parser->parse($code);
            $traverser->traverse($ast);
            return [
                'vars' => $visitor->varFindings,
                'calls' => $visitor->calls,
                'usages' => $visitor->usages,
            ];
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
