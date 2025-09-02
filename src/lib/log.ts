export function info(msg: string) {
  console.log(msg);
}
export function error(msg: string) {
  console.error(msg);
}
export function setFailed(msg: string) {
  console.error(`FAIL: ${msg}`);
  process.exitCode = 1;
}
export function getInput(name: string): string | undefined {
  // Placeholder: when running in GitHub Actions, replace with @actions/core.getInput
  const key = name.replace(/ /g, '_').toUpperCase();
  return process.env[key];
}
