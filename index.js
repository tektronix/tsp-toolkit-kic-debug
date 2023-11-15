const path = require("path")
const os = require("os")

const EXTENSION = (() =>{
    if (os.platform() === "win32") {
        return `.exe`
    } else {
        return ""
    }
})()

const PATH = path.join(__dirname, "bin")

const DEBUG_NAME = `kic-debug${EXTENSION}`
const DEBUG_EXECUTABLE = path.join(PATH, DEBUG_NAME)

module.exports = {
    DEBUG_EXECUTABLE
}
