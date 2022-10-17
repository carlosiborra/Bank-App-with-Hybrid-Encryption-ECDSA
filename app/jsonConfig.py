import json
from pathlib import Path

path = Path(__file__).parent.absolute()
JSON_PATH = str(path).replace('\\', '/') + "/database.json"


def add_money(token, amount):
    """Función para añadir dinero al usuario"""

    with open(JSON_PATH, "r", encoding="utf8") as f:
        data = json.load(f)

    money = -1
    for i in data:
        if i["token"] == token:
            print(
                f'Bienvenido: {i["usuario"]}\n\nDinero anterior: {i["dinero"]}\n')
            money = i["dinero"] + amount
            i["dinero"] += amount
            print(f'Dinero actual: {i["dinero"]}\n')

    if money == -1:
        print("Valores incorrectos\n")
        f.close()
        return -1

    with open(JSON_PATH, "w", encoding="utf8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

    print("Nueva base de datos actualizada: ", data)
    f.close()
    return money


def compare_hash(token):
    """Función para comparar el hash del token"""
    with open(JSON_PATH, "r", encoding="utf8") as f:
        data = json.load(f)

    for i in data:
        if i["token"] == token:
            return True
    return False
