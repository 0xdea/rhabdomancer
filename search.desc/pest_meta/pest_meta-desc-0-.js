searchState.loadedDescShard("pest_meta", 0, "pest meta\nA tuple returned by the validation and processing of the …\nTypes for the pest’s abstract syntax tree.\nDifferent optimizations for pest’s ASTs.\nParses, validates, processes and optimizes the provided …\nTypes and helpers for the pest’s own grammar parser.\nA helper that will unwrap the result or panic with the …\nHelpers for validating pest grammars that could help with …\natomic rule prevent implicit whitespace: inside an atomic …\nMatches either of two expressions, e.g. <code>e1 | e2</code>\nCompound atomic rules are similar to atomic rules, but …\nAll possible rule expressions\nThe top down iterator for an expression.\nMatches the rule with the given name, e.g. <code>a</code>\nMatches an exact string, case insensitively (ASCII only), …\nNegative lookahead; matches if expression doesn’t match, …\nNon-atomic rules cancel the effect of atomic rules. (their …\nThe normal rule type\nOptionally matches an expression, e.g. <code>e?</code>\nMatches a custom part of the stack, e.g. <code>PEEK[..]</code>\nPositive lookahead; matches expression without making …\nMatches an expression and pushes it to the stack, e.g. …\nMatches one character in the range, e.g. <code>&#39;a&#39;..&#39;z&#39;</code>\nMatches an expression zero or more times, e.g. <code>e*</code>\nMatches an expression an exact number of times, e.g. <code>e{n}</code>\nMatches an expression at most a number of times, e.g. <code>e{,n}</code>\nMatches an expression at least a number of times, e.g. …\nMatches an expression a number of times within a range, …\nMatches an expression one or more times, e.g. <code>e+</code>\nA grammar rule\nAll possible rule types\nMatches a sequence of two expressions, e.g. <code>e1 ~ e2</code>\nSilent rules are just like normal rules — when run, they …\nContinues to match expressions until one of the strings in …\nMatches an exact string, e.g. <code>&quot;a&quot;</code>\nThe rule’s expression\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns the iterator that steps the expression from top to …\nApplies <code>f</code> to the expression and all its children (bottom …\nApplies <code>f</code> to the expression and all its children (top to …\nThe name of the rule\nConstructs a top-down iterator from the expression.\nThe rule’s type (silent, atomic, …)\nMatches either of two expressions, e.g. <code>e1 | e2</code>\nMatches the rule with the given name, e.g. <code>a</code>\nMatches an exact string, case insensitively (ASCII only), …\nNegative lookahead; matches if expression doesn’t match, …\nOptionally matches an expression, e.g. <code>e?</code>\nThe optimized version of the pest AST’s <code>Expr</code>.\nA top-down iterator over an <code>OptimizedExpr</code>.\nThe optimized version of the pest AST’s <code>Rule</code>.\nMatches a custom part of the stack, e.g. <code>PEEK[..]</code>\nPositive lookahead; matches expression without making …\nMatches an expression and pushes it to the stack, e.g. …\nMatches one character in the range, e.g. <code>&#39;a&#39;..&#39;z&#39;</code>\nMatches an expression zero or more times, e.g. <code>e*</code>\nRestores an expression’s checkpoint\nMatches a sequence of two expressions, e.g. <code>e1 ~ e2</code>\nContinues to match expressions until one of the strings in …\nMatches an exact string, e.g. <code>&quot;a&quot;</code>\nThe optimized expression of the rule.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns a top-down iterator over the <code>OptimizedExpr</code>.\nApplies <code>f</code> to the <code>OptimizedExpr</code> bottom-up.\nApplies <code>f</code> to the <code>OptimizedExpr</code> top-down.\nThe name of the rule.\nCreates a new top down iterator from an <code>OptimizedExpr</code>.\nTakes pest’s ASTs and optimizes them\nThe type of the rule.\nA grammar comment.\nMatches either of two expressions, e.g. <code>e1 | e2</code>\nEnd-of-input\nMatches the rule with the given name, e.g. <code>a</code>\nMatches an exact string, case insensitively (ASCII only), …\nNegative lookahead; matches if expression doesn’t match, …\nOptionally matches an expression, e.g. <code>e?</code>\nAll possible parser expressions\nThe pest grammar node\nThe pest grammar rule\nMatches a custom part of the stack, e.g. <code>PEEK[..]</code>\nImport included grammar (<code>PestParser</code> class globally for …\nPositive lookahead; matches expression without making …\nMatches an expression and pushes it to the stack, e.g. …\nMatches one character in the range, e.g. <code>&#39;a&#39;..&#39;z&#39;</code>\nMatches an expression zero or more times, e.g. <code>e*</code>\nMatches an expression an exact number of times, e.g. <code>e{n}</code>\nMatches an expression at most a number of times, e.g. <code>e{,n}</code>\nMatches an expression at least a number of times, e.g. …\nMatches an expression a number of times within a range, …\nMatches an expression one or more times, e.g. <code>e+</code>\nImport included grammar (<code>PestParser</code> class globally for …\nMatches a sequence of two expressions, e.g. <code>e1 ~ e2</code>\nMatches an exact string, e.g. <code>&quot;a&quot;</code>\nA whitespace character.\nA PUSH expression.\nAn alpha character.\nAn alphanumeric character.\nAssignment operator.\nAtomic rule prefix.\nA multi-line comment.\nA single quoted character\nA choice operator.\nClosing brace for a rule.\nClosing bracket for PEEK (slice inside).\nClosing parenthesis for a branch, PUSH, etc.\nA hexadecimal code.\nA comma terminal.\nCompound atomic rule prefix.\nConverts a parser’s result (<code>Pairs</code>) to an AST\nAn escape sequence.\nThe node’s expression\nA rule expression.\nwill remove nodes that do not match <code>f</code>\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nNote: <code>include!</code> adds here a code generated from build.rs …\nA top-level comment.\nA rule of a grammar.\nThe top-level rule of a grammar.\nA hexadecimal digit.\nAn identifier.\nBranches or sequences.\nAn escaped or any character.\nA comment content.\nA quoted string.\nAn insensitive string.\nAn integer number (positive or negative).\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nA single line comment.\nA rule comment.\nA rule modifier.\nThe rule’s name\nA negative predicate.\nA newline character.\nThe rule’s parser node\nA rule node (inside terms).\nFor assigning labels to nodes.\nNon-atomic rule prefix.\nA number.\nOpening brace for a rule.\nOpening bracket for PEEK (slice inside).\nOpening parenthesis for a branch, PUSH, etc.\nAn optional operator.\nA helper that will parse using the pest grammar\nA PEEK expression.\nA positive predicate.\nPossible modifiers for a rule.\nPossible predicates for a rule.\nA double quote.\nA character range.\nA range operator.\nA helper function to rename verbose rules for the sake of …\nA repeat exact times.\nA repeat at most times.\nA repeat at least times.\nA repeat in a range.\nA repeat at least once operator.\nA repeat operator.\nA sequence operator.\nSilent rule prefix.\nA single quote.\nA space character.\nThe rule’s span\nThe node’s span\nA string.\nA tag label.\nA rule term.\nA terminal expression.\nThe rule’s type\nA unicode code.\nA grammar comment.\nEnd-of-input\nPest meta-grammar\nA whitespace character.\nA PUSH expression.\nAn alpha character.\nAn alphanumeric character.\nAssignment operator.\nAtomic rule prefix.\nA multi-line comment.\nA single quoted character\nA choice operator.\nClosing brace for a rule.\nClosing bracket for PEEK (slice inside).\nClosing parenthesis for a branch, PUSH, etc.\nA hexadecimal code.\nA comma terminal.\nCompound atomic rule prefix.\nAn escape sequence.\nA rule expression.\nA top-level comment.\nA rule of a grammar.\nThe top-level rule of a grammar.\nA hexadecimal digit.\nAn identifier.\nBranches or sequences.\nAn escaped or any character.\nA comment content.\nA quoted string.\nAn insensitive string.\nAn integer number (positive or negative).\nA single line comment.\nA rule comment.\nA rule modifier.\nA negative predicate.\nA newline character.\nA rule node (inside terms).\nFor assigning labels to nodes.\nNon-atomic rule prefix.\nA number.\nOpening brace for a rule.\nOpening bracket for PEEK (slice inside).\nOpening parenthesis for a branch, PUSH, etc.\nAn optional operator.\nA PEEK expression.\nA positive predicate.\nPossible modifiers for a rule.\nPossible predicates for a rule.\nA double quote.\nA character range.\nA range operator.\nA repeat exact times.\nA repeat at most times.\nA repeat at least times.\nA repeat in a range.\nA repeat at least once operator.\nA repeat operator.\nA sequence operator.\nSilent rule prefix.\nA single quote.\nA space character.\nA string.\nA tag label.\nA rule term.\nA terminal expression.\nA unicode code.\nChecks if <code>expr</code> is non-failing, that is it matches any …\nChecks if <code>expr</code> is non-progressing, that is the expression …\nValidates that the given <code>definitions</code> do not contain any …\nValidates the abstract syntax tree for common mistakes:\nIt checks the parsed grammar for common mistakes:\nValidates that the given <code>definitions</code> do not contain any …\nValidates that the given <code>definitions</code> do not contain any …\nValidates that the given <code>definitions</code> do not contain any …")