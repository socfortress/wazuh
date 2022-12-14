sudo /var/ossec/engine/wazuh-engine catalog update decoder/syslog/0 < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/syslog.yml 

# Apache all
sudo /var/ossec/engine/wazuh-engine catalog create decoder < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/web/apache/apache-access.yml
sudo /var/ossec/engine/wazuh-engine catalog create decoder < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/web/apache/apache-error.yml

sudo /var/ossec/engine/wazuh-engine catalog update decoder/apache-access/0 < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/web/apache/apache-access.yml
sudo /var/ossec/engine/wazuh-engine catalog update decoder/apache-error/0 < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/web/apache/apache-error.yml

sudo /var/ossec/engine/wazuh-engine catalog update environment/wazuh/0 < /home/vagrant/engine/wazuh/src/engine/ruleset/environments/wazuh-environment.yml; sudo /var/ossec/engine/wazuh-engine test -ddd

# Suricata - all
sudo /var/ossec/engine/wazuh-engine catalog create decoder < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/intrusion_detection/suricata/suricata.yml
sudo /var/ossec/engine/wazuh-engine catalog create decoder < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/intrusion_detection/suricata/suricata-http.yml
sudo /var/ossec/engine/wazuh-engine catalog create decoder < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/intrusion_detection/suricata/suricata-alert.yml
sudo /var/ossec/engine/wazuh-engine catalog create decoder < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/intrusion_detection/suricata/suricata-flow.yml

sudo /var/ossec/engine/wazuh-engine catalog update decoder/suricata/0 < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/intrusion_detection/suricata/suricata.yml 
sudo /var/ossec/engine/wazuh-engine catalog update decoder/suricata-http/0 < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/intrusion_detection/suricata/suricata-http.yml 
sudo /var/ossec/engine/wazuh-engine catalog update decoder/suricata-alert/0 < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/intrusion_detection/suricata/suricata-alert.yml 
sudo /var/ossec/engine/wazuh-engine catalog update decoder/suricata-flow/0 < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/intrusion_detection/suricata/suricata-flow.yml 

sudo /var/ossec/engine/wazuh-engine catalog update environment/wazuh/0 < /home/vagrant/engine/wazuh/src/engine/ruleset/environments/wazuh-environment.yml; 


sudo /var/ossec/engine/wazuh-engine test -ddd

# cisco - all 
sudo /var/ossec/engine/wazuh-engine catalog create decoder < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/network/cisco/cisco.yml

sudo /var/ossec/engine/wazuh-engine catalog update decoder/cisco/0 < /home/vagrant/engine/wazuh/src/engine/ruleset/decoders/network/cisco/cisco.yml 

sudo /var/ossec/engine/wazuh-engine catalog update environment/wazuh/0 < /home/vagrant/engine/wazuh/src/engine/ruleset/environments/wazuh-environment.yml