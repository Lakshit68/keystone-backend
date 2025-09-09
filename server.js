const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
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
    image: {
        type: Buffer,
        required: true,
        set: (value) => {
            if (typeof value === "string") {
                const rawBase64 = value.toString("utf-8").replace(/data:\w+\/\w+;base64,/, "").toString("base64")
                return Buffer.from(rawBase64, 'base64')
            }
            return value
        }
    },
    author: { type: String, default: 'Admin' },
    publishedAt: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
blogSchema.set('toJSON', {
    transform: (doc, ret) => {
        ret.image = ("data:image/webp;base64," + doc.image.toString('utf-8')).toString("base64")
        return ret
    }
})

const gallerySchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    images: [{
        data: {
            type: Buffer, required: true, set: (value) => {
                if (typeof value === "string") {
                    const rawBase64 = value.toString("utf-8").replace(/data:\w+\/\w+;base64,/, "").toString("base64")
                    console.log(rawBase64.toString("utf-8").slice(0, 20))
                    return Buffer.from(rawBase64, 'base64')
                }
                return value
            }
        },
        contentType: { type: String, required: true },
    }],
    publishedAt: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
gallerySchema.set('toJSON', {
    transform: (doc, ret) => {
        ret.images = doc.images.map((image) => ({
            data: ("data:image/webp;base64," + image.data.toString('utf-8')).toString("base64"),
            contentType: image.contentType
        }))
        return ret
    }
})

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
        const blog = await Blog.create({
            title,
            description,
            content,
            image,
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

        if (image) {
            updateData.image = image;
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
        const gallery = new Gallery({
            title,
            description,
            images: images.map(img => ({
                data: img.data,
                contentType: img.contentType
            }))
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

        if (images) {
            updateData.images = images;
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

// Image serving routes
app.get('/api/images/blog/:id', async (req, res) => {
    try {
        const blog = await Blog.findById(req.params.id);
        if (!blog) return res.status(404).json({ error: 'Blog not found' });

        res.set('Content-Type', blog.imageType);
        res.send(blog.image);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/images/gallery/:id/:imageIndex', async (req, res) => {
    try {
        const gallery = await Gallery.findById(req.params.id);
        console.log(req.params.id, req.params.imageIndex)
        if (!gallery) return res.status(404).json({ error: 'Gallery not found' });

        const imageIndex = parseInt(req.params.imageIndex);
        if (imageIndex >= gallery.images.length) return res.status(404).json({ error: 'Image not found' });

        const image = gallery.images[imageIndex];
        res.set('Content-Type', image.contentType);
        res.send(image.data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

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
