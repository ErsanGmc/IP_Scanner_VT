import requests


def check_ip_on_vt(ip_address, api_key):
    """
    Check the given IP address on VirusTotal using the provided API key.

    Parameters:
    - ip_address (str): The IP address to check.
    - api_key (str): The API key for accessing VirusTotal.

    Returns:
    None

    Prints the IP address, country, and last analysis results for the given IP address.
    If any analysis result is 'malicious', it prints a warning message.
    """
    api_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {
        'x-apikey': api_key
    }

    try:
        response = requests.get(api_url, headers=headers)
        response_json = response.json()

        if response.status_code == 200:
            data = response_json.get('data', {})
            
            if 'attributes' in data:
                attributes = data['attributes']
                country = attributes.get('country', 'Unknown')
                last_analysis_results = attributes.get('last_analysis_results', {})
                
                print("IP Address:", ip_address)
                print("Country:", country)
                print("")
                print("Last Analysis Results:")
                flag= False
                check_list=[]
                for engine, result in last_analysis_results.items():
                    print(f"{engine}: {result['result']}")
                    if result['result']=='malicious':   
                        check_list.append([engine,result['result']]) 
                    else:
                        continue
                if len(check_list)>0:
                    print("") 
                    print("***MALICIOUS IPs , DONT OPEN*** ")
                    print("")
                    for engine,result in check_list:
                        print(f"{engine}:{result}")
                    
                else:
                    print("Secure IP for VT But search other CTI Platforms")
                      
            else:
                print("No information available for the IP address.")

            
        else:
            print("Error occurred while checking the IP address:", response_json.get('error', {}).get('message', 'Unknown error'))

    except requests.exceptions.RequestException as e:
        print("An error occurred during the request:", str(e))

# VT Public API key
api_key = 'VT_API_KEY' 

if __name__ == '__main__':
    target_url = input("Please enter a URL: ")
    check_ip_on_vt(target_url, api_key)

