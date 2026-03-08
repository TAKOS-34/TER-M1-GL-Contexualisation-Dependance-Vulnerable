# Créer l'environnement python

```
python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt
```
A chaque nouveau terminal : `source venv/bin/activate`

# Lancer le serveur

`uvicorn main:app --reload`
