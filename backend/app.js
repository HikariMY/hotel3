const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Op } = require('sequelize');
const { sequelize, User, Hotel, Room, Booking } = require('./models');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET_KEY = 'hotel_secret_api';

// Middleware เช็ค Token
const auth = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'กรุณาเข้าสู่ระบบ' });
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token ไม่ถูกต้อง' });
        req.user = user;
        next();
    });
};

// Middleware เช็ค Admin
const isAdmin = (req, res, next) => req.user.role === 'พนักงาน' ? next() : res.status(403).json({ message: 'ไม่มีสิทธิ์' });

// 1. Auth (สมัคร/ล็อกอิน)
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password, contact_number, address } = req.body;
        const password_hash = await bcrypt.hash(password, 10);
        await User.create({ username, email, password_hash, contact_number, address, role: 'ลูกค้า' });
        res.status(201).json({ message: 'สมัครสำเร็จ' });
    } catch (err) { res.status(400).json({ error: 'อีเมลซ้ำ' }); }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    if (user && await bcrypt.compare(password, user.password_hash)) {
        const token = jwt.sign({ user_id: user.user_id, role: user.role, username: user.username }, SECRET_KEY, { expiresIn: '1d' });
        res.json({ token, role: user.role, username: user.username });
    } else {
        res.status(401).json({ message: 'อีเมล/รหัสผิด' });
    }
});

// 2. ค้นหาห้องพัก
app.get('/api/hotels', async (req, res) => {
    const { location, room_type, check_in, check_out } = req.query;
    let hotelFilter = {};
    let roomFilter = { availability: true };

    if (location) hotelFilter.location = { [Op.like]: `%${location}%` };
    if (room_type) roomFilter.room_type = { [Op.like]: `%${room_type}%` };

    if (check_in && check_out) {
        const overlaps = await Booking.findAll({
            where: {
                status: { [Op.ne]: 'ยกเลิก' },
                check_in_date: { [Op.lt]: check_out },
                check_out_date: { [Op.gt]: check_in }
            }
        });
        const bookedIds = overlaps.map(b => b.room_id);
        if (bookedIds.length > 0) roomFilter.room_id = { [Op.notIn]: bookedIds };
    }

    const hotels = await Hotel.findAll({ where: hotelFilter, include: [{ model: Room, where: roomFilter, required: true }] });
    res.json(hotels);
});

// 3. ระบบจอง (ลูกค้า)
app.post('/api/book', auth, async (req, res) => {
    try {
        const { room_id, check_in_date, check_out_date, total_amount } = req.body;
        const booking = await Booking.create({ user_id: req.user.user_id, room_id, check_in_date, check_out_date, total_amount });
        res.status(201).json({ message: 'จองสำเร็จ', booking });
    } catch (err) { res.status(500).json({ error: 'จองไม่สำเร็จ' }); }
});

app.get('/api/my-bookings', auth, async (req, res) => {
    const bookings = await Booking.findAll({ where: { user_id: req.user.user_id }, include: [{ model: Room, include: [Hotel] }] });
    res.json(bookings);
});

// 4. แอดมิน
app.get('/api/admin/bookings', auth, isAdmin, async (req, res) => {
    const bookings = await Booking.findAll({ include: [User, { model: Room, include: [Hotel] }] });
    res.json(bookings);
});

app.put('/api/admin/bookings/:id', auth, isAdmin, async (req, res) => {
    await Booking.update({ status: req.body.status }, { where: { booking_id: req.params.id } });
    res.json({ message: 'อัปเดตสำเร็จ' });
});

// รันเซิร์ฟเวอร์ + Mock Data
sequelize.sync({ force: true }).then(async () => {
    const pwd = await bcrypt.hash('1234', 10);
    await User.create({ username: 'Admin', email: 'admin@hotel.com', password_hash: pwd, role: 'พนักงาน' });
    const h1 = await Hotel.create({ hotel_name: 'Sea Breeze', location: 'Phuket' });
    await Room.create({ hotel_id: h1.hotel_id, room_type: 'Deluxe', price_per_night: 2000 });
    await Room.create({ hotel_id: h1.hotel_id, room_type: 'Suite', price_per_night: 5000 });
    app.listen(3000, () => console.log('✅ Backend API -> http://localhost:3000'));
});