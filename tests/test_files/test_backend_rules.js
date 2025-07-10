// Test backend security rules

// Server-side Open Redirect
const redirectUrl = req.query.url;
res.setHeader('Location', redirectUrl);

// Express style redirect  
app.get('/redirect', (req, res) => {
    const target = req.query.target;
    res.redirect(target);
});

// Command Injection
const userCmd = req.body.command;
child_process.exec(userCmd);

// SQL Injection
const searchTerm = req.params.search;
db.query("SELECT * FROM users WHERE name = '" + searchTerm + "'");

// Path Traversal
const filename = req.query.file;
fs.readFile(filename, (err, data) => {
    res.send(data);
}); 