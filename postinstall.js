const os = require("os");
const childProcess = require("child_process");

const osType = os.type();

/**
 * Choose postinstall script depending on OS
 */
function command() {
    if (osType === "Linux" || osType === "Darwin") {
        return "bash postinstall.sh";
    } else if (osType === "Windows_NT") {
        return "powershell.exe -NoProfile -ExecutionPolicy Bypass -File postinstall.ps1";
    }
}

childProcess.exec(command(), (error, stdout, stderr) => {
    if (error) {
        console.error(`${error}`);
        return;
    }
    console.log(`${stdout}`);
    console.error(`${stderr}`);
});
