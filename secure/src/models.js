const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: '/data/database.sqlite',
  logging: console.log, // включаем логирование SQL — удобно для демонстрации атак
});

const User = sequelize.define('User', {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  role: {
    type: DataTypes.STRING,
    defaultValue: 'user',
  },
}, {
  tableName: 'users',
  timestamps: true,
});

const Product = sequelize.define('Product', {
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  description: {
    type: DataTypes.TEXT,
  },
  price: {
    type: DataTypes.FLOAT,
    allowNull: false,
  },
  category: {
    type: DataTypes.STRING,
  },
}, {
  tableName: 'products',
  timestamps: true,
});

async function seed() {
  await sequelize.sync({ force: true });

  await User.bulkCreate([
    { username: 'admin', password: 'SuperSecretAdminPass123!', email: 'admin@shop.local', role: 'admin' },
    { username: 'alice', password: 'alicepass', email: 'alice@shop.local', role: 'user' },
    { username: 'bob', password: 'bobpass', email: 'bob@shop.local', role: 'user' },
  ]);

  await Product.bulkCreate([
    { name: 'Ноутбук Pro 15', description: 'Мощный ноутбук для работы', price: 1999.99, category: 'electronics' },
    { name: 'Беспроводная мышь', description: 'Эргономичная мышь', price: 29.99, category: 'electronics' },
    { name: 'Кофеварка', description: 'Автоматическая кофеварка', price: 89.99, category: 'home' },
    { name: 'Книга "Чистый код"', description: 'Классика для разработчиков', price: 24.99, category: 'books' },
    { name: 'Секретная заметка', description: 'FLAG{this_should_not_be_visible_via_sqli}', price: 0, category: 'internal' },
  ]);

  console.log('База данных заполнена тестовыми данными.');
}

module.exports = { sequelize, User, Product, seed };
