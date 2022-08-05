module.exports = grammar({
    name: "rego",

    extras: $ => [
        $.comment,
        /[\s\p{Zs}\uFEFF\u2060\u200B]/,
    ],

    word: $ => $.keyword,

    rules: {
        source_file: $ => optional($.module),

        // module          = package { import } policy
        module: $ => seq(
            $._package,
            repeat($._import),
            optional($.policy),
        ),

        // package         = "package" ref
        _package: $ => seq(
            $.package,
            $.ref
        ),

        // import          = "import" ref [ "as" var ]
        _import: $ => seq(
            $.import, $.ref,
            optional(seq($.as, $.var))
        ),

        // policy          = { rule }
        policy: $ => repeat1($.rule),
    
        // rule            = [ "default" ] rule-head { rule-body }
        rule: $ => seq(
            optional($.default),
            $.rule_head,
            repeat($.rule_body),
        ),

        // rule-head       = var ( rule-head-set | rule-head-obj | rule-head-func | rule-head-comp )
        rule_head: $ => seq(
            $.var,
            choice(
                //   rule-head-set   = ( "contains" term [ "if" ] ) | ( "[" term "]" )
                choice(
                    seq($.contains, $.term, optional($.if)),
                    seq("[", $.term, "]")
                ),
                
                // TODO(pavel): It doesn't make sense for these 2 rules to start with optionals
                // 
                // Fully optional rules don't make much sense here, especially considering
                // that in each case the first optional is the distinguishing factor of the 2
                // rule-head variants
        
                // OLD: rule-head-obj   = [ "[" term "]" ] [ ( ":=" | "=" ) term ] [ "if" ]
                // NEW: rule-head-obj   = "[" term "]" [ rule-head-comp ] [ "if" ]
                seq(
                    seq("[", $.term, "]"),
                    optional($.rule_head_comp),
                    optional($.if),
                ),
                
                // OLD: rule-head-func  = [ "(" rule-args ")" ] [ ( ":=" | "=" ) term ] [ "if" ]
                // NEW: rule-head-func  = "(" rule-args ")" [ rule-head-comp ]
                seq(
                    seq("(", $.rule_args, ")"),
                    optional($.rule_head_comp),
                    optional($.if),
                ),

                seq(optional($.rule_head_comp), optional($.if))
            ),
        ),

        // rule-head-comp  = ( ":=" | "=" ) term
        rule_head_comp: $ => seq($.assignment_operator, $.expr),

        // rule-args       = term { "," term }
        rule_args: $ => seq(
            $.term,
            repeat(seq(",", $.term)),
        ),

        // rule-body       = [ "else" [ ( ":=" | "=" ) term ] ] "{" query "}"
        rule_body: $ => seq(
            optional(
                seq(
                    $.else,
                    optional(
                        seq(
                          $.assignment_operator,
                          $.term,
                        ),
                    ),
                ),
            ),
            "{", $.query, "}"
        ),

        // query           = literal { ( ";" | ( [CR] LF ) ) literal }
        query: $ => seq(
            $.literal,
            repeat(
                seq(
                    choice(";", seq(optional("\r"), "\n")),
                    optional($.literal),
                ),
            ),
        ),

        // literal         = ( some-decl | expr | "not" expr ) { with-modifier }
        literal: $ => seq(
            choice($.some_decl, $.expr, seq($.not, $.expr)),
            repeat($.with_modifier),
        ),
     
        // with-modifier   = "with" term "as" term
        with_modifier: $ => seq($.with, $.term, $.as, $.term),

        // some-decl       = "some" term { "," term } { "in" expr }
        some_decl: $ => seq(
            $.some, $.term, repeat(seq(",", $.term)), repeat(seq($.in, $.expr))
        ),

        // expr            = term | expr-call | expr-infix | expr-every
        expr: $ => choice($.term, $.expr_call, $.expr_infix, $.expr_every, $.expr_parens),

        // expr-parens     = "(" expr ")"
        expr_parens: $ => prec(-1, seq(
            "(", $.expr, ")"
        )),
    
        // expr-call       = var [ "." var ] "(" [ expr { "," expr } ] ")"
        expr_call: $ => seq(
            $.var,
            optional(
                seq(".", $.var)
            ),
            "(",
            optional(
                seq($.expr, repeat(seq(",", $.expr)))
            ),
            ")",
        ),

        // expr-infix      = [ term "=" ] expr infix-operator expr
        expr_infix: $ => seq(
            /*
            FIXME: (pavel) This looks wrong and causes tree-sitter to choke out cause the rule conflicts with itself.
            I have no idea why/how the basis for infix expressions should concern itself if it's preceeded with `term =`.

            This seems to be an implementation detail of how the Rego parser works to provide useful error messages.

               https://github.com/open-policy-agent/opa/blob/main/ast/parser.go#L1103

            Follow up with Rego folks on this. For now we're gonna treat this rule as: expr-infix = expr infix-operator expr

            optional(seq($.term, "=")),
            */
            $._infix
        ),

        // _infix = expr infix-operator expr        
        _infix: $ => prec.left(1,
            seq($.expr, $.infix_operator, $.expr,),
        ),

        // expr-every      = "every" var { "," var } "in" ( term | expr-call | expr-infix ) "{" query "}"
        expr_every: $ => seq(
            $.every,
            $.var,
            repeat(seq(",", $.var)),
            $.in,
            choice($.term, $.expr_call, $.expr_infix),
            "{", $.query, "}",
        ),
    
        // term            = ref | var | scalar | array | object | set | array-compr | object-compr | set-compr
        term: $ => choice(
            $.ref,
            $.var,
            $.scalar,
            $.array,
            $.object,
            $.set,
            $.array_compr,
            $.object_compr,
            $.set_compr,
            $.membership,
        ),

        // array-compr     = "[" term "|" rule-body "]"
        array_compr: $ => seq(
            "[", $.term, "|", $.query, "]",
        ),

        // set-compr       = "{" term "|" rule-body "}"
        set_compr: $ => seq(
            "{", $.term, "|", $.query, "}",
        ),

        // object-compr    = "{" object-item "|" rule-body "}"
        object_compr: $ => seq(
            "{", $.object_item, "|", $.query, "}",
        ),

   
        // infix-operator  = bool-operator | arith-operator | bin-operator
        infix_operator: $ => choice(
            prec.left(2, $.assignment_operator), $.bool_operator, $.arith_operator, $.bin_operator
        ),

        // assignment-operator = ":=" | "="    
        assignment_operator: $ => choice($.assignment, $.unification),

        // assignment operator
        assignment: $ => ":=",

        // unification operator
        unification: $ => "=",
    
        // bool-operator   = "==" | "!=" | "<" | ">" | ">=" | "<="
        bool_operator: $ => choice(
            "==", "!=", "<", ">", ">=", "<="
        ),

        // arith-operator  = "+" | "-" | "*" | "/"
        arith_operator: $ => choice(
            "+", "-", "*", "/"
        ),

        // bin-operator    = "&" | "|"
        bin_operator: $ => choice("&", "|"),

        // ref             = ( var | array | object | set | array-compr | object-compr | set-compr | expr-call ) { ref-arg }
        ref: $ => prec.left(1,
            seq(
                choice(
                    $.var,
                    $.array,
                    $.object,
                    $.set,
                    $.array_compr,
                    $.object_compr,
                    $.set_compr,
                    $.expr_call,
                ),
                repeat($.ref_arg),
            )
        ),

        // ref-arg         = ref-arg-dot | ref-arg-brack
        ref_arg: $ => choice(
            $.ref_arg_dot,
            $.ref_arg_brack,
        ),

        // ref-arg-brack   = "[" ( scalar | var | array | object | set | "_" ) "]"
        ref_arg_brack: $ => seq(
            "[", 
            choice(
                $.scalar,
                $.var,
                $.array,
                $.object,
                $.set,
                "_",
            ),
            "]",
        ),

        // ref-arg-dot     = "." var
        ref_arg_dot: $ => seq(".", $.var),

        // var             = ( ALPHA | "_" ) { ALPHA | DIGIT | "_" }
        var: $ => /[A-Za-z_]+\w*/,

        // scalar          = string | NUMBER | TRUE | FALSE | NULL
        scalar: $ => choice(
            $.string,
            $.number,
            $.boolean,
            "null",
        ),
 
        // string          = STRING | raw-string
        string: $ => choice(
            seq(
                '"',
                repeat(
                    token.immediate(/[^\\"\n]+/)
                ),
                '"'
            ),
            $.raw_string,
        ),

        // raw-string      = "`" { CHAR-"`" } "`"
        raw_string: $ => seq(
            "`",
            repeat(/[^`]+/),
            "`",
        ),

        // array           = "[" term { "," term } "]"
        array: $ => seq(
            "[",
            $.term,
            repeat(
                seq(",", $.term)
            ),
            "]",
        ),

        // object          = "{" object-item { "," object-item } "}"
        object: $ => seq(
            "{",
            $.object_item,
            repeat(
                seq(",", $.object_item),
            ),
            "}",
        ),

        // object-item     = ( scalar | ref | var ) ":" term
        object_item: $ => seq(
            field("key", choice($.scalar, $.ref, $.var)),
            ":",
            field("value", $.term),
        ),

        // set             = empty-set | non-empty-set
        set: $ => choice($.empty_set, $.non_empty_set),

        // non-empty-set   = "{" term { "," term } "}"
        non_empty_set: $ => seq(
            "{",
            $.term,
            repeat(
                seq(",", $.term),
            ),
            "}"
        ),

        // empty-set       = "set(" ")"
        empty_set: $ => seq("set(", ")"),

        // comment
        comment: $ => token(seq('#', /.*/)),

        // boolean
        boolean: $ => choice("true", "false"),

        // membership      = scalar [ "," scalar ] "in" ref
        membership: $ => prec.left(-1, seq(
            $.scalar,
            optional(seq(",", $.scalar)),
            $.in,
            $.ref,
        )),
    
        // number
        number: $ => /\d+/,

        // not keyword 
        not: $ => "not",

        // with keyword
        with: $ => "with",

        // as keyword
        as: $ => "as",

        // in keyword
        in: $ => "in",

        // if keyword
        if: $ => "if",

        // every keyword        
        every: $ => "every",

        // else keyword
        else: $ => "else",

        // package keyword    
        package: $ => "package",
        
        // import keyword
        import: $ => "import",

        // contains keyword
        contains: $ => "contains",

        // some keyword
        some: $ => "some",

        // default keyword
        default: $ => "default",

        // match whole words
        keyword: $ => /[a-z]+/,
    }
});
