const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const cloudinary = require('cloudinary').v2;

const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Cloudinary configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI);
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
    // Seed initial admin if none exists
    (async () => {
        try {
            const existingCount = await AdminUser.countDocuments();
            if (existingCount === 0) {
                const defaultUsername = process.env.ADMIN_USERNAME || 'keystone';
                const defaultPassword = process.env.ADMIN_PASSWORD || 'keystone123';
                const passwordHash = await bcrypt.hash(defaultPassword, 10);
                await AdminUser.create({ username: defaultUsername, passwordHash });
                console.log(`Initialized admin user: ${defaultUsername}`);
            }
        } catch (e) {
            console.error('Error seeding admin user:', e.message);
        }
    })();
});



// Models
const blogSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    content: { type: String, required: true },
    imageUrl: { type: String, required: true },
    imagePublicId: { type: String },
    author: { type: String, default: 'Admin' },
    publishedAt: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const gallerySchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    images: [{
        url: { type: String, required: true },
        publicId: { type: String },
        contentType: { type: String, required: true },
    }],
    publishedAt: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const resourceSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    image: { type: Buffer, required: true },
    imageType: { type: String, required: true },
    file: { type: Buffer, required: true },
    fileType: { type: String, required: true },
    fileName: { type: String, required: true },
    category: { type: String },
    publishedAt: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Blog = mongoose.model('Blog', blogSchema);
const Gallery = mongoose.model('Gallery', gallerySchema);
const Resource = mongoose.model('Resource', resourceSchema);

// Admin user schema (single admin)
const adminUserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const AdminUser = mongoose.model('AdminUser', adminUserSchema);

// Routes

// Helper to upload a base64 or data URI image to Cloudinary
async function uploadImageToCloudinary(dataUri, folder) {
    const res = await cloudinary.uploader.upload(dataUri, {
        folder,
        resource_type: 'image',
    });
    return { url: res.secure_url, publicId: res.public_id, format: res.format };
}

// Blog routes
app.get('/api/blogs', async (req, res) => {
    try {
        const blogs = await Blog.find().sort({ createdAt: -1 });
        res.json(blogs);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/blogs/:id', async (req, res) => {
    try {
        const blog = await Blog.findById(req.params.id);
        if (!blog) return res.status(404).json({ error: 'Blog not found' });
        res.json(blog);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/blogs', async (req, res) => {
    try {
        const { title, description, content, image, author } = req.body;

        if (!image) {
            return res.status(400).json({ error: 'Image is required' });
        }

        const { url, publicId } = await uploadImageToCloudinary(image, 'blogs');

        const blog = await Blog.create({
            title,
            description,
            content,
            imageUrl: url,
            imagePublicId: publicId,
            author
        });
        await blog.save();
        res.json(blog);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/blogs/:id', async (req, res) => {
    try {
        const { title, description, content, image, author } = req.body;
        const updateData = { title, description, content, author, updatedAt: new Date() };

        // Only upload new image if provided and it's a data URI (not existing URL)
        if (image && image.startsWith('data:')) {
            const { url, publicId } = await uploadImageToCloudinary(image, 'blogs');
            updateData.imageUrl = url;
            updateData.imagePublicId = publicId;
        }

        const blog = await Blog.findByIdAndUpdate(req.params.id, updateData, { new: true });
        if (!blog) return res.status(404).json({ error: 'Blog not found' });
        res.json(blog);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/blogs/:id', async (req, res) => {
    try {
        const blog = await Blog.findByIdAndDelete(req.params.id);
        if (!blog) return res.status(404).json({ error: 'Blog not found' });
        res.json({ message: 'Blog deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Gallery routes
app.get('/api/galleries', async (req, res) => {
    try {
        const galleries = await Gallery.find().sort({ createdAt: -1 });
        res.json(galleries);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/galleries/:id', async (req, res) => {
    try {
        const gallery = await Gallery.findById(req.params.id);
        if (!gallery) return res.status(404).json({ error: 'Gallery not found' });
        res.json(gallery);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/galleries', async (req, res) => {
    try {
        const { title, description, images } = req.body;
        if (!Array.isArray(images) || images.length === 0) {
            return res.status(400).json({ error: 'At least one image is required' });
        }

        const uploaded = await Promise.all(
            images.map(async (img) => {
                const { url, publicId } = await uploadImageToCloudinary(img.data || img, 'galleries');
                return { url, publicId, contentType: img.contentType || 'image/jpeg' };
            })
        );

        const gallery = new Gallery({
            title,
            description,
            images: uploaded
        });
        await gallery.save();
        res.json(gallery);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/galleries/:id', async (req, res) => {
    try {
        const { title, description, images } = req.body;
        const updateData = { title, description, updatedAt: new Date() };

        if (Array.isArray(images)) {
            const uploaded = await Promise.all(
                images.map(async (img) => {
                    // If the client sent an existing URL, keep it; otherwise upload
                    if (typeof img === 'string' && img.startsWith('http')) {
                        return { url: img, contentType: 'image/jpeg' };
                    }
                    if (img?.data && img.data.startsWith('http')) {
                        return { url: img.data, contentType: img.contentType || 'image/jpeg' };
                    }
                    const source = img?.data || img;
                    const { url, publicId } = await uploadImageToCloudinary(source, 'galleries');
                    return { url, publicId, contentType: img.contentType || 'image/jpeg' };
                })
            );
            updateData.images = uploaded;
        }

        const gallery = await Gallery.findByIdAndUpdate(req.params.id, updateData, { new: true });
        if (!gallery) return res.status(404).json({ error: 'Gallery not found' });
        res.json(gallery);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/galleries/:id', async (req, res) => {
    try {
        const gallery = await Gallery.findByIdAndDelete(req.params.id);
        if (!gallery) return res.status(404).json({ error: 'Gallery not found' });
        res.json({ message: 'Gallery deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Resource routes
app.get('/api/resources', async (req, res) => {
    try {
        const resources = await Resource.find().sort({ createdAt: -1 });
        res.json(resources);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/resources/:id', async (req, res) => {
    try {
        const resource = await Resource.findById(req.params.id);
        if (!resource) return res.status(404).json({ error: 'Resource not found' });
        res.json(resource);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/resources', async (req, res) => {
    try {
        const { title, description, image, imageType, file, fileType, fileName, category } = req.body;
        const resource = new Resource({
            title,
            description,
            image: Buffer.from(image, 'base64'),
            imageType,
            file: Buffer.from(file, 'base64'),
            fileType,
            fileName,
            category
        });
        await resource.save();
        res.json(resource);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/resources/:id', async (req, res) => {
    try {
        const { title, description, image, imageType, file, fileType, fileName, category } = req.body;
        const updateData = { title, description, fileName, category, updatedAt: new Date() };

        if (image) {
            updateData.image = Buffer.from(image, 'base64');
            updateData.imageType = imageType;
        }

        if (file) {
            updateData.file = Buffer.from(file, 'base64');
            updateData.fileType = fileType;
        }

        const resource = await Resource.findByIdAndUpdate(req.params.id, updateData, { new: true });
        if (!resource) return res.status(404).json({ error: 'Resource not found' });
        res.json(resource);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/resources/:id', async (req, res) => {
    try {
        const resource = await Resource.findByIdAndDelete(req.params.id);
        if (!resource) return res.status(404).json({ error: 'Resource not found' });
        res.json({ message: 'Resource deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Auth routes
// First-time register: only allowed if no admin exists yet
app.post('/api/auth/register-initial', async (req, res) => {
    try {
        const existingCount = await AdminUser.countDocuments();
        if (existingCount > 0) {
            return res.status(400).json({ error: 'Admin already initialized' });
        }

        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const admin = await AdminUser.create({ username, passwordHash });

        res.json({ message: 'Admin initialized' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Login route
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const admin = await AdminUser.findOne({ username });
        if (!admin) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isValid = await bcrypt.compare(password, admin.passwordHash);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { sub: admin._id.toString(), username: admin.username, role: 'admin' },
            process.env.JWT_SECRET || 'dev-secret',
            { expiresIn: '1d' }
        );

        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Middleware to protect admin routes (can be used later)
const requireAuth = (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ')
        ? header.slice('Bearer '.length)
        : null;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
        req.user = decoded;
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
};

// Image routes are no longer required when using Cloudinary URLs

app.get('/api/images/resource/:id', async (req, res) => {
    try {
        const resource = await Resource.findById(req.params.id);
        if (!resource) return res.status(404).json({ error: 'Resource not found' });

        res.set('Content-Type', resource.imageType);
        res.send(resource.image);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/files/resource/:id', async (req, res) => {
    try {
        const resource = await Resource.findById(req.params.id);
        if (!resource) return res.status(404).json({ error: 'Resource not found' });

        res.set('Content-Type', resource.fileType);
        res.set('Content-Disposition', `attachment; filename="${resource.fileName}"`);
        res.send(resource.file);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
