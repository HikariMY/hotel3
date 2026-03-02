const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: 'database.sqlite',
    logging: false
});

const User = sequelize.define('User', {
    user_id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    username: { type: DataTypes.STRING, allowNull: false },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password_hash: { type: DataTypes.STRING, allowNull: false },
    contact_number: { type: DataTypes.STRING },
    address: { type: DataTypes.TEXT },
    role: { type: DataTypes.ENUM('ลูกค้า', 'พนักงาน'), defaultValue: 'ลูกค้า' }
}, { timestamps: false });

const Hotel = sequelize.define('Hotel', {
    hotel_id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    hotel_name: { type: DataTypes.STRING, allowNull: false },
    location: { type: DataTypes.STRING },
    address: { type: DataTypes.TEXT },
    rating: { type: DataTypes.FLOAT, defaultValue: 0 },
    contact_number: { type: DataTypes.STRING },
    description: { type: DataTypes.TEXT },
    image_url: { type: DataTypes.STRING }
}, { timestamps: false });

const Room = sequelize.define('Room', {
    room_id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    room_type: { type: DataTypes.STRING, allowNull: false },
    price_per_night: { type: DataTypes.INTEGER, allowNull: false },
    max_occupancy: { type: DataTypes.INTEGER, defaultValue: 2 },
    availability: { type: DataTypes.BOOLEAN, defaultValue: true },
    room_image_url: { type: DataTypes.STRING }
}, { timestamps: false });

const Booking = sequelize.define('Booking', {
    booking_id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    booking_date: { type: DataTypes.DATEONLY, defaultValue: Sequelize.NOW },
    check_in_date: { type: DataTypes.DATEONLY, allowNull: false },
    check_out_date: { type: DataTypes.DATEONLY, allowNull: false },
    total_amount: { type: DataTypes.INTEGER, allowNull: false },
    status: { type: DataTypes.ENUM('รอดำเนินการ', 'ยืนยัน', 'ยกเลิก'), defaultValue: 'รอดำเนินการ' }
}, { timestamps: false });

Hotel.hasMany(Room, { foreignKey: 'hotel_id' });
Room.belongsTo(Hotel, { foreignKey: 'hotel_id' });

User.hasMany(Booking, { foreignKey: 'user_id' });
Booking.belongsTo(User, { foreignKey: 'user_id' });

Room.hasMany(Booking, { foreignKey: 'room_id' });
Booking.belongsTo(Room, { foreignKey: 'room_id' });

module.exports = { sequelize, User, Hotel, Room, Booking };