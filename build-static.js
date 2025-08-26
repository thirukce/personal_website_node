const fs = require('fs');
const path = require('path');
const ejs = require('ejs');

// Create build directory
const buildDir = './build';
if (!fs.existsSync(buildDir)) {
    fs.mkdirSync(buildDir);
}

// Build static homepage from EJS template
ejs.renderFile('./views/index.ejs', { basePath: '' }, (err, html) => {
    if (err) {
        console.error('Error rendering index.ejs:', err);
        return;
    }
    
    fs.writeFileSync(path.join(buildDir, 'index.html'), html);
    console.log('✅ Generated index.html');
});

// Copy any static assets (if you have CSS/JS files)
const publicDir = './public';
if (fs.existsSync(publicDir)) {
    const copyRecursive = (src, dest) => {
        if (fs.statSync(src).isDirectory()) {
            if (!fs.existsSync(dest)) fs.mkdirSync(dest);
            fs.readdirSync(src).forEach(file => {
                copyRecursive(path.join(src, file), path.join(dest, file));
            });
        } else {
            fs.copyFileSync(src, dest);
        }
    };
    
    copyRecursive(publicDir, buildDir);
    console.log('✅ Copied static assets');
}

console.log('\n📁 Static files generated in ./build/');
console.log('📋 To deploy: Copy ./build/* to /var/www/html/');
console.log('⚠️  Note: This removes all dynamic features (login, dashboard, uploads)');
