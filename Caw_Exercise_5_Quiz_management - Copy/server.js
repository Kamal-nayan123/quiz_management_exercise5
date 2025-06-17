// =====================================
// 🔧 SETUP
// =====================================
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
app.use(cors());
app.use(express.json());

const MONGO_URI = 'mongodb://localhost:27017/quiz_platform';
const PORT = 5000;
const JWT_SECRET = 'supersecretkey';

// =====================================
// 🧱 MODELS
// =====================================

const QuestionSchema = new mongoose.Schema({
  text: String,
  type: { type: String, enum: ['multiple_choice', 'true_false', 'text'] },
  options: [String],
  correct_answer: mongoose.Schema.Types.Mixed,
  points: Number
});

const QuizSchema = new mongoose.Schema({
  title: String,
  description: String,
  time_limit: Number,
  is_public: Boolean,
  created_by: String,
  questions: [QuestionSchema]
});

const AnswerSchema = new mongoose.Schema({
  question_id: String,
  answer: mongoose.Schema.Types.Mixed
});

const QuizSessionSchema = new mongoose.Schema({
  quiz_id: String,
  user_name: String,
  started_at: Date,
  completed_at: Date,
  score: Number,
  answers: [AnswerSchema]
});

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  isAdmin: { type: Boolean, default: false }
});

const Quiz = mongoose.model('Quiz', QuizSchema);
const QuizSession = mongoose.model('QuizSession', QuizSessionSchema);
const User = mongoose.model('User', UserSchema);

// =====================================
// 🔐 AUTH MIDDLEWARE
// =====================================

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// =====================================
// 🧾 AUTH ROUTES
// =====================================

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res, next) => {
  try {
    const { name, email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashed });
    await user.save();
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
  } catch (err) {
    next(err);
  }
});

// =====================================
// 📚 QUIZ ROUTES
// =====================================

// CREATE quiz (protected)
app.post('/api/quizzes', async (req, res, next) => {
  try {
    const quiz = new Quiz(req.body);
    await quiz.save();
    res.status(201).json(quiz);
  } catch (err) {
    next(err);
  }
});

// GET all quizzes
app.get('/api/quizzes', async (req, res, next) => {
  try {
    const quizzes = await Quiz.find();
    res.json(quizzes);
  } catch (err) {
    next(err);
  }
});

// GET quiz by id
app.get('/api/quizzes/:id', async (req, res, next) => {
  try {
    const quiz = await Quiz.findById(req.params.id);
    if (!quiz) return res.status(404).json({ error: 'Quiz not found' });
    res.json(quiz);
  } catch (err) {
    next(err);
  }
});

// UPDATE quiz
app.put('/api/quizzes/:id', async (req, res, next) => {
  try {
    const quiz = await Quiz.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!quiz) return res.status(404).json({ error: 'Quiz not found' });
    res.json(quiz);
  } catch (err) {
    next(err);
  }
});

// DELETE quiz
app.delete('/api/quizzes/:id', requireAuth, async (req, res, next) => {
  try {
    await Quiz.findByIdAndDelete(req.params.id);
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// =====================================
// 🎮 QUIZ SESSION ROUTES
// =====================================

// START a session
app.post('/api/quizzes/:id/start', async (req, res, next) => {
  try {
    const { user_name } = req.body;
    const session = new QuizSession({
      quiz_id: req.params.id,
      user_name,
      started_at: new Date(),
      score: 0,
      answers: []
    });
    await session.save();
    res.status(201).json({ session_id: session._id });
  } catch (err) {
    next(err);
  }
});

// SUBMIT a session
app.post('/api/quizzes/:id/submit', async (req, res, next) => {
  try {
    const { session_id, answers } = req.body;
    const session = await QuizSession.findById(session_id);
    const quiz = await Quiz.findById(session.quiz_id);
    if (!session || !quiz) return res.status(404).json({ error: 'Not found' });

    let score = 0;
    const evaluated = answers.map(ans => {
      const q = quiz.questions.id(ans.question_id);
      if (q && q.correct_answer == ans.answer) score += q.points;
      return ans;
    });

    session.answers = evaluated;
    session.completed_at = new Date();
    session.score = score;
    await session.save();

    res.json({ score });
  } catch (err) {
    next(err);
  }
});

// GET session result
app.get('/api/quizzes/:id/results/:session_id', async (req, res, next) => {
  try {
    const session = await QuizSession.findById(req.params.session_id);
    if (!session) return res.status(404).json({ error: 'Result not found' });
    res.json(session);
  } catch (err) {
    next(err);
  }
});

// GET analytics
app.get('/api/quizzes/:id/analytics', async (req, res, next) => {
  try {
    const sessions = await QuizSession.find({ quiz_id: req.params.id });
    const total = sessions.length;
    const avgScore = total ? sessions.reduce((sum, s) => sum + s.score, 0) / total : 0;
    res.json({ totalAttempts: total, avgScore });
  } catch (err) {
    next(err);
  }
});

// =====================================
// ❌ ERROR HANDLER
// =====================================
app.use((err, req, res, next) => {
  console.error('ERROR:', err);
  res.status(500).json({ error: err.message });
});

// =====================================
// 🚀 START SERVER
// =====================================
mongoose.connect(MONGO_URI)
  .then(() => app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`)))
  .catch(err => console.error('❌ MongoDB connection failed:', err));
