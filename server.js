const express = require("express");
const app = express();

app.use(express.json());

app.get("/", (req, res) => {
    res.send("API ONLINE");
});

app.post("/V1/validate", async (req, res) => {

    const { license_key, hwid } = req.body;

    if (!license_key) {
        return res.json({
            success: false,
            error: "NO_KEY"
        });
    }

    return res.json({
        success: true,
        username: "BLACKHAWK",
        plan: "LIFETIME"
    });

});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("API RUNNING");
});