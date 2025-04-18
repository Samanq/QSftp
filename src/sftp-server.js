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
              // Add proper file type flags - 0o040000 is S_IFDIR (directory), 0o100000 is S_IFREG (regular file)
              const mode = stats.isDirectory() ? 0o40755 : 0o100644;
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
              // Add proper file type flags - 0o040000 is S_IFDIR (directory), 0o100000 is S_IFREG (regular file)
              const mode = stats.isDirectory() ? 0o40755 : 0o100644;
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
            let normalizedPath = filepath === '.' ? '' : path.normalize(filepath.replace(/^\/+/, ''));
            const resolvedPath = resolvePath(filepath);
            console.log('REALPATH normalized path:', normalizedPath);
            console.log('REALPATH resolved path:', resolvedPath);
            
            // Check if the path exists and get stats
            try {
              const stats = fs.statSync(resolvedPath);
              // Add proper file type flags - 0o040000 is S_IFDIR (directory), 0o100000 is S_IFREG (regular file)
              const mode = stats.isDirectory() ? 0o40755 : 0o100644;
              console.log('REALPATH stats:', {
                isDirectory: stats.isDirectory(),
                mode: mode.toString(8),
                path: resolvedPath
              });
              
              sftpStream.name(reqid, [{
                filename: '/' + normalizedPath, // Always return absolute paths
                longname: '/' + normalizedPath,
                attrs: {
                  size: stats.size,
                  uid: 0,
                  gid: 0,
                  mode: mode,
                  atime: stats.atime.getTime() / 1000,
                  mtime: stats.mtime.getTime() / 1000
                }
              }]);
            } catch (err) {
              console.log('REALPATH error:', err.message);
              // If the path doesn't exist, just return the normalized path anyway
              sftpStream.name(reqid, [{
                filename: '/' + normalizedPath,
                longname: '/' + normalizedPath,
                attrs: {
                  size: 0,
                  uid: 0,
                  gid: 0,
                  mode: 0o40755, // Always assume directory for non-existent paths
                  atime: 0,
                  mtime: 0
                }
              }]);
            }
          });

          sftpStream.on('OPENDIR', (reqid, dir) => {
            console.log('Opening directory:', dir);
            const resolvedPath = resolvePath(dir);
            console.log('OPENDIR resolved path:', resolvedPath);
            
            try {
              if (fs.existsSync(resolvedPath) && fs.statSync(resolvedPath).isDirectory()) {
                const handle = Buffer.from(`dir-${Date.now()}`);
                const files = fs.readdirSync(resolvedPath);
                console.log('Directory contents:', files);
                openDirectories.set(handle.toString(), {
                  path: resolvedPath,
                  files: files,
                  index: 0
                });
                sftpStream.handle(reqid, handle);
              } else {
                console.log('Directory not found or not a directory:', resolvedPath);
                sftpStream.status(reqid, 2); // SSH_FX_NO_SUCH_FILE
              }
            } catch (err) {
              console.log('OPENDIR error:', err.message);
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
            console.log('Flags binary:', flags.toString(2));
            
            // Define the standard flags for better debugging
            const flagsMap = {
              O_RDONLY: 0,
              O_WRONLY: 1,
              O_RDWR: 2,
              O_CREAT: 64,
              O_TRUNC: 512,
              O_APPEND: 1024
            };
            
            // Log which flags are set
            console.log('Detected flags:', 
              Object.entries(flagsMap)
                .filter(([_, value]) => (flags & value) === value)
                .map(([key]) => key)
                .join(', '));
            
            const resolvedPath = resolvePath(filename);
            console.log('OPEN resolved path:', resolvedPath);
            
            try {
              // Check if this is a write operation (WRONLY or RDWR)
              const isWriteRequest = (flags & flagsMap.O_WRONLY) || (flags & flagsMap.O_RDWR);
              const isCreateRequest = flags & flagsMap.O_CREAT;
              
              console.log('Write request:', isWriteRequest);
              console.log('Create request:', isCreateRequest);
              
              // For file uploads, we create the file even if O_CREAT isn't set
              // This handles clients like the sftp command that don't set O_CREAT
              if (isWriteRequest) {
                console.log('Creating file for writing:', resolvedPath);
                
                // Ensure the directory exists
                const dirPath = path.dirname(resolvedPath);
                if (!fs.existsSync(dirPath)) {
                  console.log('Creating parent directories:', dirPath);
                  fs.mkdirSync(dirPath, { recursive: true });
                }
                
                // Always create the file for write operations
                // Use 'w' for TRUNC, otherwise 'a+' which preserves content
                const shouldTruncate = flags & flagsMap.O_TRUNC;
                const writeFlag = shouldTruncate ? 'w' : 'a+';
                
                try {
                  fs.closeSync(fs.openSync(resolvedPath, writeFlag));
                  console.log('File created or opened for writing');
                } catch (err) {
                  console.log('Error creating/opening file:', err.message);
                  sftpStream.status(reqid, 4); // SSH_FX_FAILURE
                  return;
                }
                
                const handle = Buffer.from(resolvedPath);
                sftpStream.handle(reqid, handle);
                console.log('File handle sent to client');
                return;
              }
              
              // Regular file open for reading
              if (fs.existsSync(resolvedPath)) {
                const stats = fs.statSync(resolvedPath);
                if (!stats.isFile()) {
                  console.log('Not a regular file:', resolvedPath);
                  sftpStream.status(reqid, 4); // SSH_FX_FAILURE
                  return;
                }
                
                const handle = Buffer.from(resolvedPath);
                sftpStream.handle(reqid, handle);
                console.log('Existing file handle sent to client');
              } else {
                console.log('File not found:', resolvedPath);
                sftpStream.status(reqid, 2); // SSH_FX_NO_SUCH_FILE
              }
            } catch (err) {
              console.log('OPEN error:', err.message);
              sftpStream.status(reqid, 4); // SSH_FX_FAILURE
            }
          });

          sftpStream.on('WRITE', (reqid, handle, offset, data) => {
            const filePath = handle.toString(); // Convert handle back to file path
            console.log(`WRITE request for: ${filePath}, offset: ${offset}, data length: ${data.length}`);
            
            try {
              // Make sure the file exists before attempting to write
              if (!fs.existsSync(filePath)) {
                console.log('File not found for writing:', filePath);
                sftpStream.status(reqid, 2); // SSH_FX_NO_SUCH_FILE
                return;
              }
              
              // Open the file for writing with position
              const fd = fs.openSync(filePath, 'r+');
              try {
                fs.writeSync(fd, data, 0, data.length, offset);
                console.log(`Successfully wrote ${data.length} bytes to ${filePath} at offset ${offset}`);
                sftpStream.status(reqid, 0); // SSH_FX_OK
              } catch (writeErr) {
                console.log('Write error:', writeErr.message);
                sftpStream.status(reqid, 4); // SSH_FX_FAILURE
              } finally {
                fs.closeSync(fd);
              }
            } catch (err) {
              console.log('WRITE error:', err.message);
              sftpStream.status(reqid, 4); // SSH_FX_FAILURE
            }
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

          sftpStream.on('MKDIR', (reqid, path, attrs) => {
            console.log('MKDIR request for:', path);
            const resolvedPath = resolvePath(path);
            console.log('MKDIR resolved path:', resolvedPath);

            try {
              if (!fs.existsSync(resolvedPath)) {
                fs.mkdirSync(resolvedPath, { recursive: true });
                console.log('Directory created:', resolvedPath);
                sftpStream.status(reqid, 0); // SSH_FX_OK
              } else {
                console.log('Directory already exists:', resolvedPath);
                sftpStream.status(reqid, 4); // SSH_FX_FAILURE (already exists)
              }
            } catch (err) {
              console.log('MKDIR error:', err.message);
              sftpStream.status(reqid, 4); // SSH_FX_FAILURE
            }
          });

          sftpStream.on('SETSTAT', (reqid, path, attrs) => {
            console.log('SETSTAT request for:', path);
            const resolvedPath = resolvePath(path);
            console.log('SETSTAT resolved path:', resolvedPath);

            try {
              if (fs.existsSync(resolvedPath)) {
                if (attrs.mode !== undefined) {
                  fs.chmodSync(resolvedPath, attrs.mode);
                }
                if (attrs.uid !== undefined && attrs.gid !== undefined) {
                  fs.chownSync(resolvedPath, attrs.uid, attrs.gid);
                }
                console.log('Attributes updated for:', resolvedPath);
                sftpStream.status(reqid, 0); // SSH_FX_OK
              } else {
                console.log('Path does not exist:', resolvedPath);
                sftpStream.status(reqid, 2); // SSH_FX_NO_SUCH_FILE
              }
            } catch (err) {
              console.log('SETSTAT error:', err.message);
              sftpStream.status(reqid, 4); // SSH_FX_FAILURE
            }
          });

          sftpStream.on('REMOVE', (reqid, path) => {
            console.log('REMOVE request for:', path);
            const resolvedPath = resolvePath(path);
            console.log('REMOVE resolved path:', resolvedPath);

            try {
              if (fs.existsSync(resolvedPath)) {
                fs.unlinkSync(resolvedPath);
                console.log('File removed:', resolvedPath);
                sftpStream.status(reqid, 0); // SSH_FX_OK
              } else {
                console.log('File does not exist:', resolvedPath);
                sftpStream.status(reqid, 2); // SSH_FX_NO_SUCH_FILE
              }
            } catch (err) {
              console.log('REMOVE error:', err.message);
              sftpStream.status(reqid, 4); // SSH_FX_FAILURE
            }
          });

          sftpStream.on('RMDIR', (reqid, path) => {
            console.log('RMDIR request for:', path);
            const resolvedPath = resolvePath(path);
            console.log('RMDIR resolved path:', resolvedPath);

            try {
              if (fs.existsSync(resolvedPath) && fs.statSync(resolvedPath).isDirectory()) {
                fs.rmdirSync(resolvedPath);
                console.log('Directory removed:', resolvedPath);
                sftpStream.status(reqid, 0); // SSH_FX_OK
              } else {
                console.log('Directory not found or not a directory:', resolvedPath);
                sftpStream.status(reqid, 2); // SSH_FX_NO_SUCH_FILE
              }
            } catch (err) {
              console.log('RMDIR error:', err.message);
              sftpStream.status(reqid, 4); // SSH_FX_FAILURE
            }
          });
        });
      });
    });
  }
);

server.listen(2222, '127.0.0.1', () => {
  console.log('SFTP server listening on port 2222');
});
