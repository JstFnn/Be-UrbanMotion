const multer = require('multer');
const path = require('path');


const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, 'src/public/uploads/'); // Directory where images will be stored
    },
    filename: (req, file, cb) => {
      // Give the file a unique name
      const fileExtension = path.extname(file.originalname);
      cb(null, Date.now() + fileExtension); // Generate a unique file name using timestamp
    },
  });
  
  // Create a file filter (optional) to allow only certain types of files (e.g., images)
  const fileFilter = (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true); // Accept the file
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG, and GIF are allowed.'), false);
    }
  };
  
  // Set up multer instance with storage and file filter options
  const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5 MB
    fileFilter: fileFilter,
  });


module.exports = upload;