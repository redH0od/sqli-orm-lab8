/**
 * ============================================================
 *  ВНИМАНИЕ: ЭТО УЧЕБНОЕ ПРИЛОЖЕНИЕ С ПРЕДНАМЕРЕННЫМИ УЯЗВИМОСТЯМИ
 *  Никогда не используйте этот код в продакшене!
 *  Цель: показать, как НЕПРАВИЛЬНОЕ использование Sequelize ORM
 *  открывает дверь для SQL Injection, даже если "ORM защищает".
 * ============================================================
 *
 * Уязвимые эндпоинты:
 *   GET  /api/products/search?category=...   -> sequelize.literal() с конкатенацией строк
 *   GET  /api/products/filter?sort=...        -> небезопасная сортировка через literal
 *   POST /api/login                           -> Op-инъекция через JSON (req.body передаётся в where напрямую)
 *   GET  /api/users/raw?id=...                -> classic raw query() с конкатенацией
 */

const express = require('express');
const bodyParser = require('body-parser');
const { Sequelize, Op } = require('sequelize');
const { sequelize, User, Product, seed } = require('./models');

const app = express();
app.use(bodyParser.json());

// -------------------- Главная страница --------------------
app.get('/', (req, res) => {
  res.send(`
    <h1>Уязвимое приложение (Sequelize ORM)</h1>
    <p>Эндпоинты:</p>
    <ul>
      <li>GET  /api/products/search?category=electronics</li>
      <li>GET  /api/products/filter?sort=price</li>
      <li>POST /api/login  { "username": "...", "password": "..." }</li>
      <li>GET  /api/users/raw?id=1</li>
    </ul>
    <p>Примеры payload'ов — см. README.md</p>
  `);
});

// =====================================================================
// УЯЗВИМОСТЬ 1: sequelize.literal() с конкатенацией пользовательского ввода
// Разработчик хотел сделать "умный" поиск по категории, но собрал
// SQL-условие вручную через template string и передал в literal().
// =====================================================================
app.get('/api/products/search', async (req, res) => {
  const { category } = req.query;

  try {
    // ОПАСНО: пользовательский ввод напрямую попадает в SQL через literal()
    const products = await Product.findAll({
      where: sequelize.literal(`category = '${category}'`),
    });

    res.json({ count: products.length, products });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// PAYLOAD (UNION-based):
//   /api/products/search?category=nonexistent' UNION SELECT id, username, password, role, '1','1','1' FROM users--
//   (количество и типы колонок нужно подобрать под таблицу products)

// =====================================================================
// УЯЗВИМОСТЬ 2: небезопасная динамическая сортировка через literal()
// =====================================================================
app.get('/api/products/filter', async (req, res) => {
  const { sort = 'id', category } = req.query;

  try {
    const where = category ? { category } : {};

    const products = await Product.findAll({
      where,
      // ОПАСНО: имя колонки для ORDER BY берётся из запроса без валидации
      order: sequelize.literal(`${sort}`),
    });

    res.json({ count: products.length, products });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// PAYLOAD (boolean / time-based blind, т.к. результат не виден напрямую):
//   /api/products/filter?sort=(SELECT CASE WHEN (1=1) THEN id ELSE id END)
//   /api/products/filter?sort=(CASE WHEN (SELECT password FROM users WHERE username='admin') LIKE 'a%' THEN id ELSE -id END)

// =====================================================================
// УЯЗВИМОСТЬ 3: Operator Injection через JSON body (Sequelize Op)
// Разработчик передаёт req.body прямо в where(), думая, что ORM
// "сам всё проверит". Но если в JSON прислать оператор Sequelize
// в виде ключа ($gt, $ne и т.п. при включённых aliases / либо через
// прямые объекты), логика проверки может быть полностью обойдена.
// =====================================================================
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // ОПАСНО: весь объект из тела запроса передаётся как условие where.
    // Если username или password — это объект вида {"ne": null} / {"$ne": null}
    // (в зависимости от версии Sequelize и настроек operatorsAliases),
    // итоговое условие превращается в "username != NULL AND password != NULL",
    // что вернёт первого пользователя из таблицы (обычно admin).
    const user = await User.findOne({
      where: {
        username: username,
        password: password,
      },
    });

    if (!user) {
      return res.status(401).json({ error: 'Неверные учетные данные' });
    }

    res.json({
      message: 'Вход выполнен успешно',
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// PAYLOAD (Operator Injection, обход аутентификации без знания пароля):
//   POST /api/login
//   Content-Type: application/json
//   {
//     "username": { "$ne": null },
//     "password": { "$ne": null }
//   }
//   Результат: вход как первый пользователь в таблице (admin), без знания пароля!

// =====================================================================
// УЯЗВИМОСТЬ 4: Классический raw query с конкатенацией строк
// =====================================================================
app.get('/api/users/raw', async (req, res) => {
  const { id } = req.query;

  try {
    // ОПАСНО: прямая конкатенация в raw SQL запрос
    const [results] = await sequelize.query(
      `SELECT id, username, email, role FROM users WHERE id = ${id}`
    );

    res.json({ results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// PAYLOAD (UNION-based, классическая SQLi):
//   /api/users/raw?id=0 UNION SELECT id, username, password, role FROM users--
//   /api/users/raw?id=1 OR 1=1

// -------------------- Запуск --------------------
const PORT = process.env.PORT || 3000;

(async () => {
  await seed();
  app.listen(PORT, () => {
    console.log(`Уязвимое приложение запущено на http://localhost:${PORT}`);
  });
})();
