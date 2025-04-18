import express, { Request, Response } from 'express';
import authRouter from './routes/auth';
import nodemailer from 'nodemailer';
import multer from 'multer';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { authMiddleware, requireRole } from './middleware/authMiddleware';
import { asyncHandler } from './utils/asyncHandler';


dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Determine environment
const isProduction = process.env.NODE_ENV === 'production';

// Get the frontend origin from environment variables
const allowedOrigins = [
  process.env.FRONTEND_ORIGIN_PROD || "https://gwb-payroll-automation-client.vercel.app",
  process.env.FRONTEND_ORIGIN_LOCAL || "http://localhost:5173"
];

// Enable CORS for all routes based on environment
app.use(cors({
  origin: allowedOrigins,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true // Important: required for cookies to work cross-domain
}));

// Body parser middleware
app.use(express.json());

// Cookie parser middleware
app.use(cookieParser());

// Auth routes
app.use(authRouter);

// Multer setup for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'hotmail',
  auth: {
    user: process.env.OUTLOOK_EMAIL,
    pass: process.env.OUTLOOK_PASSWORD,
  },
});

// Protected route that requires authentication
app.post(
  '/api/send-payslip-to-email',
  authMiddleware,
  upload.single('file'),
  asyncHandler(async (req: Request, res: Response) => {
    if (!req.file) {
      return res.status(400).send('No file uploaded');
    }

    const mailOptions: nodemailer.SendMailOptions = {
      from: process.env.OUTLOOK_EMAIL,
      to: req.body.to,
      subject: req.body.subject,
      attachments: [
        {
          filename: req.file.originalname,
          content: req.file.buffer,
        },
      ],
    };

    if (req.body.html) {
      mailOptions.html = req.body.html;
      mailOptions.text = req.body.text || req.body.html.replace(/<[^>]*>/g, '');
    } else if (req.body.text) {
      mailOptions.text = req.body.text;
    }

    const info = await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Email sent successfully!', info });
  })
);


// Admin-only route example
app.get(
  '/api/admin/users',
  authMiddleware,
  requireRole('admin'),
  asyncHandler(async (req: Request, res: Response) => {
    res.json({ message: 'This is admin-only content' });
  })
);


// Health check endpoint
app.get('/api/health', (req: Request, res: Response) => {
  res.status(200).send('Server is running');
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});