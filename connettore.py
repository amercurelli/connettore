import os
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

import os
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
import time


class TemplateConnector:
    def __init__(self):
        #mi serve per caricare il file yml con le spec
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"

        # controllo file di spec e se non trova impedisce errori futuri
        if os.path.isfile(config_file_path):
            with open(config_file_path, 'r') as config_file:
                config = yaml.load(config_file, Loader=yaml.SafeLoader)
        else:
            config = {}
            print(f"Config file not found at {config_file_path}, using default configuration.")
        #inizio com con open e carico file
        self.helper = OpenCTIConnectorHelper(config)

        self.custom_attribute = get_config_variable(
            "TEMPLATE_ATTRIBUTE", ["template", "attribute"], config
        )
        #future spec vanno aggiunte

#esecuzione/errore del connettore
if __name__ == "__main__":
    try:
        template_connector = TemplateConnector()

        template_connector.run()
    except Exception as e:
        print(f"An error occurred: {e}")
        time.sleep(10)
        exit(0)
