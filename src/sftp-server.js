const { Server } = require('ssh2');
const fs = require('fs');
const path = require('path');

const USERS = {
  'username': 'password' // Replace with your desired username and password
};

const ROOT_DIR = path.join(__dirname, 'sftp-root'); // Directory for SFTP file storage
if (!fs.existsSync(ROOT_DIR)) {
  fs.mkdirSync(ROOT_DIR);
}

function resolvePath(filepath) {
  // Handle root path specially
  if (filepath === '/' || filepath === '.') {
    return ROOT_DIR;
  }
  // Remove leading slashes and normalize
  const normalizedPath = path.normalize(filepath.replace(/^\/+/, ''));
  const resolvedPath = path.join(ROOT_DIR, normalizedPath);
  console.log('Path resolution:', {
    original: filepath,
    normalized: normalizedPath,
    resolved: resolvedPath
  });
  return resolvedPath;
}

const server = new Server(
  {
    hostKeys: [fs.readFileSync('host.key')], // Add passphrase here
    debug: console.log,
    algorithms: {
      kex: [
        'ecdh-sha2-nistp256',
        'ecdh-sha2-nistp384',
        'ecdh-sha2-nistp521',
        'diffie-hellman-group-exchange-sha256',
        'diffie-hellman-group14-sha1'
      ],
      cipher: [
        'aes128-ctr',
        'aes192-ctr',
        'aes256-ctr',
        'aes128-gcm',
        'aes256-gcm'
      ]
    }
  },
  (client) => {
    console.log('Client connected!');
    
    client.on('authentication', (ctx) => {
      console.log(`Authentication attempt [${ctx.method}]: ${ctx.username}`);
      
      if (ctx.method === 'none') {
        // Allow none method but don't authenticate
        return ctx.reject(['password']);
      }
      
      if (ctx.method === 'password') {
        if (USERS[ctx.username] === ctx.password) {
          console.log('Authentication successful');
          return ctx.accept();
        }
      }
      
      console.log('Authentication failed');
      ctx.reject();
    });

    client.on('ready', () => {
      console.log('Client authenticated!');
      
      client.on('session', (accept) => {
        const session = accept();

        session.on('sftp', (accept) => {
          console.log('SFTP session started');
          const sftpStream = accept();

          const openDirectories = new Map(); // Map to track open directory handles

          // Add LSTAT handler - this is what get command uses first
          sftpStream.on('LSTAT', (reqid, filepath) => {
            console.log('LSTAT request for:', filepath);
            const resolvedPath = resolvePath(filepath);
            console.log('LSTAT resolved path:', resolvedPath);
            
            try {
              const stats = fs.statSync(resolvedPath);
              const mode = stats.isDirectory() ? 0o755 : 0o644 | 0o100000; // Add S_IFREG flag for regular files
              console.log('LSTAT file stats:', {
                size: stats.size,
                isDirectory: stats.isDirectory(),
                mode: mode.toString(8),
                path: resolvedPath
              });
              sftpStream.attrs(reqid, {
                mode: mode,
                size: stats.size,
                uid: 0,
                gid: 0,
                atime: stats.atime.getTime() / 1000,
                mtime: stats.mtime.getTime() / 1000
              });
            } catch (err) {
              console.log('LSTAT error:', err.message, 'for path:', resolvedPath);
              sftpStream.status(reqid, 2); // SSH_FX_NO_SUCH_FILE
            }
          });

          sftpStream.on('STAT', (reqid, filepath) => {
            console.log('\nSTAT command received');
            console.log('STAT request for:', filepath);
            const resolvedPath = resolvePath(filepath);
            console.log('STAT resolved path:', resolvedPath);
            console.log('File exists:', fs.existsSync(resolvedPath));
            
            try {
              const stats = fs.statSync(resolvedPath);
              const mode = stats.isDirectory() ? 0o755 : 0o644 | 0o100000; // Add S_IFREG flag for regular files
              console.log('File stats:', {
                size: stats.size,
                isDirectory: stats.isDirectory(),
                mode: mode.toString(8),
                path: resolvedPath
              });
              sftpStream.attrs(reqid, {
                mode: mode,
                size: stats.size,
                uid: 0,
                gid: 0,
                atime: stats.atime.getTime() / 1000,
                mtime: stats.mtime.getTime() / 1000
              });
            } catch (err) {
              console.log('STAT error:', err.message);
              sftpStream.status(reqid, 2); // SSH_FX_NO_SUCH_FILE
            }
          });

          sftpStream.on('REALPATH', (reqid, filepath) => {
            console.log('REALPATH request for:', filepath);
            // Handle both absolute and relative paths
            const normalizedPath = filepath === '.' ? '' : path.normalize(filepath.replace(/^\/+/, ''));
            console.log('Normalized path:', normalizedPath);
            
            sftpStream.name(reqid, [{
              filename: '/' + normalizedPath, // Always return absolute paths
              longname: '/' + normalizedPath,
              attrs: {
                size: 0,
                uid: 0,
                gid: 0,
                mode: 0o755,
                atime: 0,
                mtime: 0
              }
            }]);
          });

          sftpStream.on('OPENDIR', (reqid, dir) => {
            console.log('Opening directory:', dir);
            const dirPath = dir === '/' ? ROOT_DIR : path.join(ROOT_DIR, dir);
            if (fs.existsSync(dirPath) && fs.statSync(dirPath).isDirectory()) {
              const handle = Buffer.from(`dir-${Date.now()}`);
              const files = fs.readdirSync(dirPath);
              console.log('Directory contents:', files);
              openDirectories.set(handle.toString(), {
                path: dirPath,
                files: files,
                index: 0
              });
              sftpStream.handle(reqid, handle);
            } else {
              console.log('Directory not found:', dirPath);
              sftpStream.status(reqid, 2); // SSH_FX_NO_SUCH_FILE
            }
          });

          sftpStream.on('READDIR', (reqid, handle) => {
            const handleKey = handle.toString();
            console.log('Reading directory with handle:', handleKey);
            const dirInfo = openDirectories.get(handleKey);

            if (!dirInfo) {
              console.log('Invalid handle:', handleKey);
              sftpStream.status(reqid, 2);
              return;
            }

            if (dirInfo.index >= dirInfo.files.length) {
              console.log('End of directory reached');
              sftpStream.name(reqid, []);
              return;
            }

            const currentFile = dirInfo.files[dirInfo.index];
            const fullPath = path.join(dirInfo.path, currentFile);
            const stats = fs.statSync(fullPath);
            
            const entry = {
              filename: currentFile,  // Use just the filename, not the full path
              longname: `${stats.isDirectory() ? 'd' : '-'}rw-r--r-- 1 owner group ${stats.size} ${stats.mtime.toLocaleDateString()} ${currentFile}`,
              attrs: {
                size: stats.size,
                uid: 0,
                gid: 0,
                mode: stats.isDirectory() ? 0o755 : 0o644,
                atime: stats.atime.getTime() / 1000,
                mtime: stats.mtime.getTime() / 1000
              }
            };

            dirInfo.index++;
            openDirectories.set(handleKey, dirInfo);
            sftpStream.name(reqid, [entry]);
          });

          sftpStream.on('OPEN', (reqid, filename, flags, attrs) => {
            console.log('\nOPEN command received');
            console.log('OPEN request for:', filename, 'flags:', flags);
            const resolvedPath = resolvePath(filename);
            console.log('OPEN resolved path:', resolvedPath);
            
            try {
              const stats = fs.statSync(resolvedPath);
              if (!stats.isFile()) {
                console.log('Not a regular file:', resolvedPath);
                sftpStream.status(reqid, 4); // SSH_FX_FAILURE
                return;
              }
              
              const fd = fs.openSync(resolvedPath, 'r');
              fs.closeSync(fd);
              
              const handle = Buffer.from(resolvedPath);
              sftpStream.handle(reqid, handle);
            } catch (err) {
              console.log('OPEN error:', err.message);
              sftpStream.status(reqid, 2);
            }
          });

          sftpStream.on('WRITE', (reqid, handle, offset, data) => {
            const filePath = handle.toString(); // Convert handle back to file path
            console.log(`WRITE request for: ${filePath}, offset: ${offset}, data length: ${data.length}`);
            fs.writeFileSync(filePath, data, { flag: offset === 0 ? 'w' : 'r+' }); // Write or append data
            sftpStream.status(reqid, 0); // Indicate success
          });

          sftpStream.on('READ', (reqid, handle, offset, length) => {
            console.log('\nREAD command received');
            const filePath = handle.toString(); // Convert handle back to file path
            console.log(`READ request for: ${filePath}, offset: ${offset}, length: ${length}`);
            
            if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
              console.log('File not found or invalid handle:', filePath);
              sftpStream.status(reqid, 2); // SSH_FX_NO_SUCH_FILE
              return;
            }

            const buffer = Buffer.alloc(length);
            const fd = fs.openSync(filePath, 'r');
            const bytesRead = fs.readSync(fd, buffer, 0, length, offset);
            fs.closeSync(fd);

            if (bytesRead > 0) {
              sftpStream.data(reqid, buffer.slice(0, bytesRead));
            } else {
              sftpStream.status(reqid, 1); // SSH_FX_EOF
            }
          });

          sftpStream.on('CLOSE', (reqid, handle) => {
            const handleKey = handle.toString();
            if (openDirectories.has(handleKey)) {
              openDirectories.delete(handleKey); // Clean up the handle
              console.log('Closing directory handle:', handleKey);
            }
            sftpStream.status(reqid, 0); // Indicate success
          });
        });
      });
    });
  }
);

server.listen(2222, '127.0.0.1', () => {
  console.log('SFTP server listening on port 2222');
});
