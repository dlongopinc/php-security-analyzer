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
            private $warnings = [];
            private $unnecessaryHtmlspecialcharsWarnings = [];

            private function addUnnecessaryHtmlspecialcharsWarning(Node $node, string $reason): void
            {
                $this->unnecessaryHtmlspecialcharsWarnings[] = [
                    'line' => $node->getStartLine(),
                    'message' => 'Unnecessary htmlspecialchars usage',
                    'detail' => $reason,
                    'type' => 'unnecessary_htmlspecialchars'
                ];
            }

            public function __construct(PrettyPrinter $printer)
            {
                $this->printer = $printer;
            }

            public function getWarnings(): array
            {
                return array_merge($this->warnings, $this->unnecessaryHtmlspecialcharsWarnings);
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

            private function isHtmlOutputContext(Node $node): bool
            {
                // Check for echo statements and PHP short tags
                if (
                    $node instanceof Node\Stmt\Echo_ ||
                    $node instanceof Node\Scalar\EncapsedStringPart ||
                    $node instanceof Node\Stmt\InlineHTML
                ) {
                    return true;
                }

                // Check for print statements
                if (
                    $node instanceof Node\Expr\FuncCall &&
                    $node->name instanceof Node\Name &&
                    $node->name->toString() === 'print'
                ) {
                    return true;
                }

                // Check for template engine calls
                if (
                    $node instanceof Node\Expr\MethodCall &&
                    $node->name instanceof Node\Identifier
                ) {
                    $methodName = strtolower($node->name->toString());
                    if (in_array($methodName, ['render', 'display', 'view'])) {
                        return true;
                    }
                }

                return false;
            }

            private function checkUnnecessaryHtmlspecialchars(Node $node): void
            {
                // Pastikan ini adalah pemanggilan htmlspecialchars
                if (
                    !($node instanceof Node\Expr\FuncCall) ||
                    !($node->name instanceof Node\Name) ||
                    $node->name->toString() !== 'htmlspecialchars'
                ) {
                    return;
                }

                // Cek argumen htmlspecialchars
                if (empty($node->args)) {
                    return;
                }

                $arg = $node->args[0]->value;
                $context = $node;

                // Cek jika digunakan dalam konteks SQL
                $inSqlContext = false;
                while ($context = $context->getAttribute('parent')) {
                    if ($this->isInSqlContext($context)) {
                        $this->addUnnecessaryHtmlspecialcharsWarning(
                            $node,
                            'Variable used in SQL context should use prepared statements instead of htmlspecialchars'
                        );
                        return;
                    }

                    // Cek jika digunakan dalam bind_param atau prepared statements
                    if (
                        $context instanceof Node\Expr\MethodCall &&
                        $context->name instanceof Node\Identifier
                    ) {
                        $methodName = strtolower($context->name->toString());
                        if (in_array($methodName, ['bind_param', 'bindvalue', 'execute'])) {
                            $this->addUnnecessaryHtmlspecialcharsWarning(
                                $node,
                                'No need for htmlspecialchars when using prepared statements'
                            );
                            return;
                        }
                    }
                }

                // Cek jika digunakan dalam operasi database lainnya
                if ($arg instanceof Node\Expr\Variable) {
                    $varName = $arg->name;
                    $sqlRelatedNames = ['query', 'sql', 'stmt', 'where', 'filter'];
                    foreach ($sqlRelatedNames as $sqlName) {
                        if (stripos($varName, $sqlName) !== false) {
                            $this->addUnnecessaryHtmlspecialcharsWarning(
                                $node,
                                'SQL-related variable should not use htmlspecialchars'
                            );
                            return;
                        }
                    }
                }
            }

            private function isSecurityRelatedCall(Node $node): bool
            {
                if (
                    $node instanceof Node\Expr\FuncCall &&
                    $node->name instanceof Node\Name
                ) {
                    if ($node->name->toString() === 'htmlspecialchars') {
                        // Periksa penggunaan htmlspecialchars yang tidak perlu
                        $this->checkUnnecessaryHtmlspecialchars($node);
                        return true;
                    }
                }
                return false;
            }

            private function isSqlKeyword(string $str): bool
            {
                $keywords = [
                    'SELECT',
                    'INSERT',
                    'UPDATE',
                    'DELETE',
                    'WHERE',
                    'FROM',
                    'JOIN',
                    'LEFT JOIN',
                    'RIGHT JOIN',
                    'INNER JOIN',
                    'GROUP BY',
                    'ORDER BY',
                    'LIMIT',
                    'OFFSET',
                    'BETWEEN',
                    'AND',
                    'OR',
                    'IN',
                    'LIKE',
                    'SUM',
                    'COUNT',
                    'COALESCE'
                ];
                foreach ($keywords as $keyword) {
                    if (stripos($str, $keyword) !== false) {
                        return true;
                    }
                }
                return false;
            }

            private function isArrayContainingQueries(Node $node): bool
            {
                // Check if it's an array being built with SQL conditions
                if (
                    $node instanceof Node\Expr\ArrayDimFetch &&
                    $node->var instanceof Node\Expr\Variable
                ) {
                    $varName = $node->var->name;
                    // Look for common filter array names
                    if (in_array($varName, ['filters', 'conditions', 'where', 'clauses'])) {
                        return true;
                    }
                }
                return false;
            }

            private function isInSqlContext(Node $node): bool
            {
                // First check the node itself
                if ($this->isArrayContainingQueries($node)) {
                    return true;
                }

                // Check variable name patterns that typically indicate SQL usage
                if ($node instanceof Node\Expr\Variable && is_string($node->name)) {
                    $varName = strtolower($node->name);
                    if (in_array($varName, ['query', 'sql', 'stmt', 'filterquery', 'wherequery', 'searchquery'])) {
                        return true;
                    }
                }

                $parent = $node;
                while ($parent = $parent->getAttribute('parent')) {
                    // Check for SQL string concatenation
                    if ($parent instanceof Node\Expr\BinaryOp\Concat) {
                        $str = $this->printer->prettyPrintExpr($parent);
                        if ($this->isSqlKeyword($str)) {
                            return true;
                        }
                    }

                    // Check for SQL string assignment
                    if ($parent instanceof Node\Expr\Assign) {
                        $str = $this->printer->prettyPrintExpr($parent->expr);
                        if ($this->isSqlKeyword($str)) {
                            return true;
                        }
                    }

                    // Check for array elements that will be used in SQL
                    if ($this->isArrayContainingQueries($parent)) {
                        return true;
                    }

                    // Check if the variable is used in a query method
                    if (
                        $parent instanceof Node\Expr\MethodCall &&
                        $parent->name instanceof Node\Identifier
                    ) {
                        $methodName = strtolower($parent->name->toString());
                        if (in_array($methodName, ['query', 'prepare', 'execute'])) {
                            return true;
                        }
                    }

                    // Check for implode of SQL conditions
                    if (
                        $parent instanceof Node\Expr\FuncCall &&
                        $parent->name instanceof Node\Name &&
                        $parent->name->toString() === 'implode'
                    ) {
                        return true;
                    }
                }
                return false;
            }

            private function isDatabaseOperation(Node $node): bool
            {
                // Check direct database operations
                if (
                    $node instanceof Node\Expr\MethodCall &&
                    $node->name instanceof Node\Identifier
                ) {
                    $methodName = strtolower($node->name->toString());
                    if (in_array($methodName, ['bind_param', 'execute', 'prepare', 'query'])) {
                        return true;
                    }
                }

                // Check if node is in SQL context
                return $this->isInSqlContext($node);
            }

            public function enterNode(Node $node)
            {
                if ($node instanceof Node\Expr\Assign) {
                    $var = $node->var;
                    $expr = $node->expr;

                    if ($var instanceof Node\Expr\Variable && is_string($var->name)) {
                        $name = $var->name;
                        $isArray = false;
                        $reason = [];
                        $secured = false;
                        $needsEscaping = false;
                        $isSuperglobal = false;

                        // Detect assignment from superglobals
                        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
                            if (in_array($expr->name, ['_POST', '_GET', '_REQUEST', '_COOKIE', '_SESSION'])) {
                                $isSuperglobal = true;
                                $isArray = true;
                                $reason[] = 'superglobal_assignment';
                            }
                        } elseif ($expr instanceof Node\Expr\ArrayDimFetch) {
                            if (
                                $expr->var instanceof Node\Expr\Variable &&
                                is_string($expr->var->name) &&
                                in_array($expr->var->name, ['_POST', '_GET', '_REQUEST', '_COOKIE', '_SESSION'])
                            ) {
                                $isSuperglobal = true;
                                $reason[] = 'superglobal_element_assignment';
                            }
                        }

                        // Analyze variable context for SQL and HTML usage
                        if ($this->isInSqlContext($node)) {
                            $needsEscaping = false;
                            $reason[] = 'used_in_sql_query';
                            // Add concise warning about SQL injection
                            $this->warnings[] = [
                                'line' => $node->getLine(),
                                'message' => 'Using prepared statements is recommended',
                                'suggestion' => 'Use: $stmt = $db->prepare("..."); $stmt->bind_param("s", $var);'
                            ];
                        } else {
                            // Check if it's used in HTML output or other contexts
                            $checkNode = $node;
                            while ($checkNode = $checkNode->getAttribute('parent')) {
                                if ($this->isHtmlOutputContext($checkNode)) {
                                    $needsEscaping = true;
                                    $reason[] = 'html_output_context';
                                    break;
                                }
                                if ($this->isDatabaseOperation($checkNode)) {
                                    $needsEscaping = false;
                                    $reason[] = 'database_operation';
                                    break;
                                }
                            }
                        }

                        // Check if the value is being secured with htmlspecialchars
                        if (
                            $expr instanceof Node\Expr\FuncCall &&
                            $expr->name instanceof Node\Name &&
                            $expr->name->toString() === 'htmlspecialchars'
                        ) {
                            $secured = true;
                            $reason[] = 'secured_with_htmlspecialchars';
                            $needsEscaping = false;
                        }

                        // Detect htmlspecialchars assignments
                        if (
                            $expr instanceof Node\Expr\FuncCall &&
                            $expr->name instanceof Node\Name
                        ) {
                            $funcName = $expr->name->toString();
                            if ($funcName === 'htmlspecialchars') {
                                $secured = true;
                                $reason[] = 'htmlspecialchars';
                            } else if ($funcName === 'array_keys') {
                                // Check if first argument is a superglobal
                                if (
                                    !empty($expr->args[0]) &&
                                    $expr->args[0]->value instanceof Node\Expr\Variable &&
                                    is_string($expr->args[0]->value->name) &&
                                    in_array($expr->args[0]->value->name, ['_POST', '_GET', '_REQUEST', '_COOKIE', '_SESSION'])
                                ) {
                                    $isArray = true;
                                    $reason[] = 'array_keys_superglobal';
                                }
                            }
                        }

                        // Array literal: [ ... ] or array(...)
                        if ($expr instanceof Node\Expr\Array_) {
                            $isArray = true;
                            $reason[] = 'array literal';
                        }

                        // Assigned from superglobal variable: $_POST, $_GET, etc.
                        if ($expr instanceof Node\Expr\Variable && is_string($expr->name) && in_array($expr->name, ['_POST', '_GET', '_REQUEST', '_COOKIE', '_SESSION'])) {
                            $isArray = true;
                            $reason[] = 'assigned from superglobal';
                        }

                        // Assigned from superglobal element: $_POST['x'] -> not a whole array
                        if ($expr instanceof Node\Expr\ArrayDimFetch && $expr->var instanceof Node\Expr\Variable && is_string($expr->var->name) && in_array($expr->var->name, ['_POST', '_GET', '_REQUEST', '_COOKIE', '_SESSION'])) {
                            $isArray = false;
                            $reason[] = 'assigned from superglobal element';
                        }

                        // Assigned from function call that obviously returns array: array_keys(), array_map(), etc.
                        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name) {
                            $fname = strtolower($expr->name->toString());
                            $arrayFuncs = ['array_keys', 'array_values', 'array_map', 'array_filter', 'explode', 'preg_split', 'range', 'glob'];
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
                    // Detect the array being iterated
                    $expr = $node->expr;
                    if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
                        $this->varFindings[] = [
                            'name' => $expr->name,
                            'line' => $node->getLine(),
                            'is_array' => true,
                            'reasons' => ['foreach_source']
                        ];
                    }

                    // Detect value variable from foreach
                    $vars = $this->collectVarsFromExpr($node->valueVar);
                    foreach ($vars as $varName) {
                        $this->varFindings[] = [
                            'name' => $varName,
                            'line' => $node->getLine(),
                            'is_array' => false,
                            'reasons' => ['foreach_value']
                        ];
                    }

                    // Detect key variable if exists
                    if ($node->keyVar !== null) {
                        $vars = $this->collectVarsFromExpr($node->keyVar);
                        foreach ($vars as $varName) {
                            $this->varFindings[] = [
                                'name' => $varName,
                                'line' => $node->getLine(),
                                'is_array' => false,
                                'reasons' => ['foreach_key']
                            ];
                        }
                    }

                    // Keep existing array detection
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

                    // Mark SQL-related functions
                    $isSqlFunction = in_array($fname, [
                        'mysqli_query',
                        'mysql_query',
                        'pdo_query',
                        'mysqli_prepare',
                        'mysqli_stmt_bind_param'
                    ]);

                    $this->calls[] = [
                        'type' => 'function',
                        'name' => $fname,
                        'line' => $node->getLine(),
                        'args' => array_map(function ($a) {
                            return $this->printer->prettyPrintExpr($a->value);
                        }, $node->args),
                        'vars' => array_values(array_unique($vars)),
                        'is_sql' => $isSqlFunction
                    ];
                }

                if ($node instanceof Node\Expr\MethodCall) {
                    $mname = null;
                    if ($node->name instanceof Node\Identifier) $mname = $node->name->toString();
                    $vars = [];

                    // Mark SQL-related methods
                    $isSqlMethod = in_array(strtolower($mname), [
                        'query',
                        'prepare',
                        'execute',
                        'bind_param'
                    ]);
                    foreach ($node->args as $a) {
                        $vars = array_merge($vars, $this->collectVarsFromExpr($a->value));
                    }
                    $this->calls[] = [
                        'type' => 'method',
                        'name' => $mname,
                        'line' => $node->getLine(),
                        'is_sql' => $isSqlMethod,
                        'args' => array_map(function ($a) {
                            return $this->printer->prettyPrintExpr($a->value);
                        }, $node->args),
                        'vars' => array_values(array_unique($vars))
                    ];
                }

                if ($node instanceof Node\Expr\StaticCall) {
                    $mname = null;
                    if ($node->name instanceof Node\Identifier) $mname = $node->name->toString();
                    $vars = [];
                    foreach ($node->args as $a) {
                        $vars = array_merge($vars, $this->collectVarsFromExpr($a->value));
                    }
                    $this->calls[] = ['type' => 'static', 'name' => $mname, 'line' => $node->getLine(), 'args' => array_map(function ($a) {
                        return $this->printer->prettyPrintExpr($a->value);
                    }, $node->args), 'vars' => array_values(array_unique($vars))];
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
                'secured' => array_filter($visitor->varFindings, function ($v) {
                    return in_array('htmlspecialchars', $v['reasons'] ?? []);
                })
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
