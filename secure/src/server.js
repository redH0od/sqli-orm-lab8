/**
 * ============================================================
 *  ЗАЩИЩЁННАЯ ВЕРСИЯ
 *  Те же эндпоинты, что и в /vulnerable, но с правильным
 *  использованием Sequelize ORM. Сравните с server.js
 *  из vulnerable/, чтобы увидеть разницу.
 * ============================================================
 *
 * Принципы защиты:
 *  1. Никогда не использовать sequelize.literal() / sequelize.query()
 *     с конкатенацией пользовательского ввода.
 *  2. Параметризованные запросы (bind / replacements) для raw SQL.
 *  3. Whitelist допустимых значений для ORDER BY, имён колонок и т.п.
 *  4. Явная валидация типов входных данных (никогда не доверять
 *     структуре JSON из req.body при построении where).
 *  5. Хэширование паролей (bcrypt) + сравнение хэшей, а не значений.
 */

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const { sequelize, User, Product, seed } = require('./models');

const app = express();
app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.send(`
    <h1>Защищённое приложение (Sequelize ORM)</h1>
    <p>Те же эндпоинты, что и в уязвимой версии, но безопасные:</p>
    <ul>
      <li>GET  /api/products/search?category=electronics</li>
      <li>GET  /api/products/filter?sort=price</li>
      <li>POST /api/login  { "username": "...", "password": "..." }</li>
      <li>GET  /api/users/raw?id=1</li>
    </ul>
  `);
});

// =====================================================================
// ЗАЩИТА 1: используем обычный объект where вместо sequelize.literal()
// Sequelize сам построит параметризованный запрос (prepared statement).
// =====================================================================
app.get('/api/products/search', async (req, res) => {
  const { category } = req.query;

  try {
    // Дополнительно: валидация типа входных данных.
    if (category !== undefined && typeof category !== 'string') {
      return res.status(400).json({ error: 'Некорректный параметр category' });
    }

    const where = {};
    if (category) {
      where.category = category; // безопасно: Sequelize экранирует значение
    }

    const products = await Product.findAll({ where });

    res.json({ count: products.length, products });
  } catch (err) {
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// =====================================================================
// ЗАЩИТА 2: whitelist допустимых полей и направлений сортировки
// =====================================================================
const SORTABLE_FIELDS = ['id', 'name', 'price', 'category', 'createdAt'];
const SORT_DIRECTIONS = ['ASC', 'DESC'];

app.get('/api/products/filter', async (req, res) => {
  const { sort = 'id', direction = 'ASC', category } = req.query;

  try {
    if (!SORTABLE_FIELDS.includes(sort)) {
      return res.status(400).json({ error: 'Недопустимое поле сортировки' });
    }

    const dir = direction.toUpperCase();
    if (!SORT_DIRECTIONS.includes(dir)) {
      return res.status(400).json({ error: 'Недопустимое направление сортировки' });
    }

    const where = {};
    if (category && typeof category === 'string') {
      where.category = category;
    }

    const products = await Product.findAll({
      where,
      order: [[sort, dir]], // безопасный синтаксис order
    });

    res.json({ count: products.length, products });
  } catch (err) {
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// =====================================================================
// ЗАЩИТА 3: строгая проверка типов входных данных + bcrypt
// Никогда не передаём req.body напрямую в where().
// Явно требуем, чтобы username/password были строками.
// =====================================================================
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // КЛЮЧЕВАЯ ЗАЩИТА: отклоняем всё, что не является примитивной строкой.
    // Это блокирует Operator Injection вида { "username": { "$ne": null } },
    // так как объект не пройдёт проверку typeof === 'string'.
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'username и password должны быть строками' });
    }

    if (username.length === 0 || username.length > 100) {
      return res.status(400).json({ error: 'Некорректный username' });
    }

    const user = await User.findOne({
      where: { username }, // безопасно: значение - строго строка
    });

    // Сравниваем хэш пароля, а не значение напрямую.
    // (в seed-данных для простоты пароли хранятся как есть -
    //  в реальном проекте они должны храниться как bcrypt-хэши)
    const passwordMatches = user && (await comparePassword(password, user.password));

    if (!user || !passwordMatches) {
      return res.status(401).json({ error: 'Неверные учетные данные' });
    }

    res.json({
      message: 'Вход выполнен успешно',
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (err) {
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// Вспомогательная функция: поддерживает как bcrypt-хэши, так и
// сравнение plain-text (для демо-данных из seed()).
async function comparePassword(plain, stored) {
  if (stored.startsWith('$2a$') || stored.startsWith('$2b$')) {
    return bcrypt.compare(plain, stored);
  }
  return plain === stored;
}

// =====================================================================
// ЗАЩИТА 4: параметризованный raw query (replacements)
// =====================================================================
app.get('/api/users/raw', async (req, res) => {
  const { id } = req.query;

  try {
    const numericId = Number(id);
    if (!Number.isInteger(numericId) || numericId <= 0) {
      return res.status(400).json({ error: 'id должен быть положительным целым числом' });
    }

    // Безопасно: параметризованный запрос через replacements.
    // Sequelize подставит значение как bound-параметр в prepared statement.
    const [results] = await sequelize.query(
      'SELECT id, username, email, role FROM users WHERE id = :id',
      {
        replacements: { id: numericId },
      }
    );

    res.json({ results });
  } catch (err) {
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// -------------------- Запуск --------------------
const PORT = process.env.PORT || 3000;

(async () => {
  await seed();
  app.listen(PORT, () => {
    console.log(`Защищённое приложение запущено на http://localhost:${PORT}`);
  });
})();
