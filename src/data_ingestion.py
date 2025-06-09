import requests
import os

def download_data(sources):
    os.makedirs('data', exist_ok=True)
    for source in sources:
        if source['enabled']:
            url = source['url']
            output = os.path.join('data', source['output'])
            response = requests.get(url)
            response.raise_for_status()
            with open(output, 'wb') as f:
                f.write(response.content)
