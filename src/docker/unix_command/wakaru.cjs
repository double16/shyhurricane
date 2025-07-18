#!/usr/bin/env node
const {unpack, detect} = require("unpacker");
const {unpack: wakaru_unpack} = require("@wakaru/unpacker");
const {runDefaultTransformationRules, runTransformationRules} = require("@wakaru/unminify");

const wakaru_1_prettify_rules = ['prettier', 'module-mapping', 'un-curly-braces', 'un-sequence-expression', 'un-variable-merging', 'un-assignment-merging'];
const wakaru_2_prepare_rules = ['un-runtime-helper', 'un-esm', 'un-enum'];
const wakaru_3_tranform_no_lebab_rules = ['un-export-rename', 'un-use-strict', 'un-esmodule-flag', 'un-boolean', 'un-undefined', 'un-infinity', 'un-typeof', 'un-numeric-literal', 'un-template-literal', 'un-bracket-notation', 'un-return', 'un-while-loop', 'un-indirect-call', 'un-type-constructor', 'un-builtin-prototype', 'un-sequence-expression', 'un-flip-comparions']

const wakaru_4_advanced_rules = ['un-import-rename', 'smart-inline', 'smart-rename', 'un-optional-chaining', 'un-nullish-coalescing', 'un-conditionals', 'un-sequence-expression', 'un-parameters', 'un-argument-spread', 'un-jsx', 'un-es6-class', 'un-async-await']

const rules = [
    null, // all rules
    wakaru_1_prettify_rules + wakaru_2_prepare_rules + wakaru_3_tranform_no_lebab_rules + wakaru_4_advanced_rules + ['prettier'],
    wakaru_1_prettify_rules + wakaru_2_prepare_rules + wakaru_3_tranform_no_lebab_rules + ['prettier'],
    wakaru_1_prettify_rules + wakaru_2_prepare_rules + ['prettier'],
    wakaru_1_prettify_rules + ['prettier'], // prettify
    ['prettier'],
];

let data = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => data += chunk);

process.stdin.on("end", async () => {
    try {
        // Step 1: Detect and unpack classic eval(p,a,c,k,e,d) form
        let eval_unpacked = data;
        if (detect(data)) {
            try {
                eval_unpacked = unpack(data).replace(/\\'/g, "'");
            } catch (err) {
            }
        }

        // Step 2: Use Wakaru to unpack modules
        let wakaru_source = eval_unpacked;
        try {
            const {modules} = wakaru_unpack(eval_unpacked);
            let modules_code = modules.map(m => m.code.toString()).join("\n");
            if (modules_code.length > (wakaru_source.length / 2)) {
                wakaru_source = modules_code;
            }
        } catch (err) {
        }

        // Step 3: Apply un-minification
        let unminified = wakaru_source;
        for (const rules0 of rules) {
            try {
                if (rules0) {
                    const {code} = await runTransformationRules({source: wakaru_source}, rules0);
                    unminified = code;
                } else {
                    const {code} = await runDefaultTransformationRules({source: wakaru_source});
                    unminified = code;
                }
                break
            } catch (err) {
                // try the next rule
            }
        }

        // TODO: use webcrack once it installs again

        console.log(unminified);
    } catch (err) {
        console.log(data);
        console.log("\n\n/*");
        console.log("Error during unpacking:", err);
        console.log("*/");
    }
});
