import pandas as pd
from collections import Counter

# Функция для обработки файла и подсчёта баллов по мерам защиты
def process_threat_file(file_path):
    # Чтение CSV или XLSX файла
    if file_path.endswith('.xlsx'):
        df = pd.read_excel(file_path)
    elif file_path.endswith('.csv'):
        df = pd.read_csv(file_path)
    else:
        raise ValueError("Неверный формат файла. Ожидается .xlsx или .csv.")

    # Проверяем, что столбец 'Меры защиты' существует в данных
    if 'Меры защиты' not in df.columns:
        raise ValueError("В файле нет столбца 'Меры защиты'")

    # Очистка столбца от посторонних символов (например, "_x000d_")
    df['Меры защиты'] = df['Меры защиты'].replace('_x000d_', '', regex=True)

    # Подсчёт количества каждого уникального значения в колонке 'Меры защиты'
    protection_measures = Counter(df['Меры защиты'])

    # Сортируем меры защиты по убыванию
    sorted_measures = protection_measures.most_common()

    # Вывод результатов
    print("Перечень уникальных мер защиты и их вклад:")
    for measure, score in sorted_measures:
        print(f"{measure}: {score} баллов")

    return df, sorted_measures

# Функция для маппинга мер защиты с NIST CSF и CIS Controls
def map_to_frameworks(sorted_measures):
    # Маппинг с NIST CSF
    nist_mapping = {
        'Access Control': 'PR.AC-1',
        'Data Protection': 'PR.DS-1',
        'Network Security': 'PR.PT-5',
        'Incident Response': 'DE.CM-1',
        'System Integrity': 'PR.IP-3',
        'Security Monitoring': 'DE.CM-2',
        # добавьте нужные меры и их соответствия
    }

    # Маппинг с CIS Controls
    cis_mapping = {
        'Access Control': 'CIS Control 4',
        'Data Protection': 'CIS Control 13',
        'Incident Response': 'CIS Control 17',
        # добавьте нужные меры и их соответствия
    }

    # Составляем таблицу с результатами
    results = []
    for measure, score in sorted_measures:
        nist_csf = nist_mapping.get(measure, "Маппинг не найден")
        cis_control = cis_mapping.get(measure, "Маппинг не найден")
        # Добавляем measure как "Наименование меры защиты" для соответствия количеству колонок
        results.append([measure, measure, score, nist_csf, cis_control])

    # Создаём DataFrame для результатов
    result_df = pd.DataFrame(results, columns=["Код меры защиты", "Наименование меры защиты", "Баллы", "Мера из NIST CSF", "Мера из CIS Controls"])

    return result_df

# Указываем путь к файлу
file_path = r'C:\Users\Ilya\Desktop\mapping script\per_ugroz.xlsx'  # замените на нужный путь к файлу

# Обрабатываем файл и получаем отсортированный список мер
df, sorted_measures = process_threat_file(file_path)

# Выполняем маппинг и получаем результат
result_df = map_to_frameworks(sorted_measures)

# Выводим итоговую таблицу в Excel
result_df.to_excel(r'C:\Users\Ilya\Desktop\mapping script\processed_measures.xlsx', index=False)

# Опционально: Выводим результат в консоль
print(result_df)
