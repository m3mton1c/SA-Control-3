# 1. Установливаем зависимости
pip install -r requirements.txt

# 2. Создаем таблицы
python app/init_db.py

# 3. Запусткаем сервер
uvicorn app.main:app --reload
