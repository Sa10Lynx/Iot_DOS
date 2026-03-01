import requests
import threading

URL = "http://127.0.0.1:8000"

def flood():
    while True:
        try:
            requests.get(URL)
        except:
            pass

threads = []
for _ in range(20):
    t = threading.Thread(target=flood)
    t.start()
    threads.append(t)

for t in threads:
    t.join()
