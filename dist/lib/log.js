"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.info = info;
exports.error = error;
exports.setFailed = setFailed;
exports.getInput = getInput;
function info(msg) {
    console.log(msg);
}
function error(msg) {
    console.error(msg);
}
function setFailed(msg) {
    console.error(`FAIL: ${msg}`);
    process.exitCode = 1;
}
function getInput(name) {
    // Placeholder: when running in GitHub Actions, replace with @actions/core.getInput
    const key = name.replace(/ /g, '_').toUpperCase();
    return process.env[key];
}
