import json
from pathlib import Path

path = Path(__file__).parent.absolute()
JSON_PATH = str(path).replace('\\', '/') + "/database.json"


def add_money(token, amount):
    print(token, amount)
    """Función para añadir dinero al usuario"""
    with open(JSON_PATH, "r", encoding="utf8") as f:
        data = json.load(f)

    money = -1
    for i in data:
        if i["token"] == token:
            print(
                f'Bienvenido: {i["usuario"]}\nDinero anterior: {i["dinero"]}')
            money = i["dinero"] + amount
            i["dinero"] += amount
            print(f'Dinero actual: {i["dinero"]}')

    if money == -1:
        print("Valores incorrectos")
        f.close()
        return -1

    with open(JSON_PATH, "w", encoding="utf8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

    print(data)
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


# add_money("e770708a8b682abd84de7851950e00479563c4edb57c2af0e77001b28c49887f", 100)

# compare_hash("e770708a8b682abd84de7851950e00479563c4edb57c2af0e77001b28c49887f")
