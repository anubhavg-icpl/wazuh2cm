# SIEM-Case Management Integration Platform

**Copyright © 2015-2020 Infopercept Consulting**
**Property of Infopercept Consulting**
**Contact: info@infopercept.com**

---

## Overview

A robust integration platform that seamlessly connects SIEM with Case Management for advanced threat detection and incident response automation.

**Reference:** [Using SIEM and Case Management for Threat Protection](https://wazuh.com/blog/using-wazuh-and-thehive-for-threat-protection-and-incident-response/)

---

## 🚀 Quick Start

### Prerequisites
- OSSEC/SIEM installation
- Case Management instance running
- Python 3.x environment
- Administrative access

### Installation

1. **Clone the repository**
```bash
cd /opt/
sudo git clone https://github.com/infopercept/siem2cm.git
```

2. **Install dependencies**
```bash
sudo /var/ossec/framework/python/bin/pip3 install -r /opt/siem2cm/requirements.txt
```

3. **Deploy integration scripts**
```bash
sudo cp /opt/siem2cm/custom-invinsense2cm.py /var/ossec/integrations/custom-invinsense2cm.py
sudo cp /opt/siem2cm/custom-invinsense2cm /var/ossec/integrations/custom-invinsense2cm
```

4. **Set permissions**
```bash
sudo chmod 755 /var/ossec/integrations/custom-invinsense2cm.py
sudo chmod 755 /var/ossec/integrations/custom-invinsense2cm
sudo chown root:ossec /var/ossec/integrations/custom-invinsense2cm.py
sudo chown root:ossec /var/ossec/integrations/custom-invinsense2cm
```

---

## ⚙️ Configuration

### 1. OSSEC Configuration

Edit `/var/ossec/etc/ossec.conf` and add the following integration block:

```xml
<integration>
    <name>custom-invinsense2cm</name>
    <hook_url>http://localhost:9000</hook_url>
    <api_key>YOUR_CM_API_KEY</api_key>
    <alert_format>json</alert_format>
</integration>
```

#### Configuration Parameters:

| Parameter | Description | Example |
|-----------|-------------|---------|
| **name** | Integration identifier (do not modify) | `custom-invinsense2cm` |
| **hook_url** | Case Management instance URL | `http://localhost:9000` |
| **api_key** | Case Management API key with alert creation permissions | `YOUR_API_KEY` |
| **alert_format** | Data format for alerts (do not modify) | `json` |

### 2. Apply Configuration

Restart OSSEC to apply changes:
```bash
sudo /var/ossec/bin/ossec-control restart
```

---

## 🔧 Advanced Settings

### Debug Mode

Enable detailed logging by modifying `/var/ossec/integrations/custom-invinsense2cm.py`:

```python
# Change from:
debug_enabled = False

# To:
debug_enabled = True
```

### Alert Filtering

Control alert volume by setting severity thresholds:

```python
# In /var/ossec/integrations/custom-invinsense2cm.py

# SIEM rules threshold (default: 0)
lvl_threshold = 5

# Suricata rules threshold (default: 3)
suricata_lvl_threshold = 3
```

Events with severity levels equal to or greater than these thresholds will be forwarded to Case Management.

---

## 📊 Monitoring

### Check Integration Status
```bash
# View integration logs
tail -f /var/ossec/logs/integrations.log

# Check for errors
grep ERROR /var/ossec/logs/integrations.log
```

### Verify Alert Creation
Monitor Case Management dashboard for incoming alerts from SIEM integration.

---

## 🔒 Security Best Practices

1. **API Key Security**
   - Create a dedicated Case Management user for integration
   - Grant minimal permissions (alert creation only)
   - Rotate API keys regularly

2. **Network Security**
   - Use HTTPS for Case Management connection
   - Implement firewall rules between SIEM and Case Management
   - Monitor integration logs for anomalies

3. **Alert Management**
   - Configure appropriate thresholds to prevent alert fatigue
   - Regularly review and tune detection rules
   - Implement alert deduplication where necessary

---

## 📚 Documentation

- [SIEM Rules Classification](https://documentation.wazuh.com/3.12/user-manual/ruleset/rules-classification.html)
- [Case Management API Documentation](https://github.com/CaseManagement-Project/CM-Docs/blob/master/api/README.md)
- [Integration Troubleshooting Guide](https://github.com/infopercept/siem2cm/wiki)

---

## संस्कृतम् (Sanskrit Documentation)

### परिचयः (Introduction)

एषः प्रकल्पः SIEM तथा Case Management इत्येतयोः मध्ये सेतुः अस्ति। सुरक्षा-घटनानां स्वचालित-प्रबन्धनाय एतत् साधनम् उपयुज्यते।

### स्थापना-विधिः (Installation Method)

१. **कोड-संग्रहस्य प्रतिलिपिः**
```bash
cd /opt/
sudo git clone https://github.com/infopercept/siem2cm.git
```

२. **आवश्यक-साधनानां स्थापना**
```bash
sudo /var/ossec/framework/python/bin/pip3 install -r /opt/siem2cm/requirements.txt
```

३. **संरचना-समायोजनम्**
   - ossec.conf फाइले एकीकरण-खण्डं योजयन्तु
   - API कुञ्जी स्थापयन्तु
   - सेवां पुनः प्रारभन्तु

### महत्त्वपूर्णाः सेटिंग्स् (Important Settings)

- **lvl_threshold**: घटना-स्तरस्य न्यूनतम-सीमा
- **debug_enabled**: विस्तृत-लॉगिंग-सक्रियकरणम्
- **suricata_lvl_threshold**: Suricata-नियमानां सीमा

### समस्या-निवारणम् (Troubleshooting)

यदि कश्चित् दोषः दृश्यते, तर्हि:
- /var/ossec/logs/integrations.log फाइलं परीक्षताम्
- debug_mode सक्रियं कुर्वन्तु
- API कुञ्जी प्रमाणीकरणं परीक्षताम्

---

## 🤝 Support

For issues, questions, or contributions:
- **Email:** info@infopercept.com
- **GitHub Issues:** [Report a bug](https://github.com/infopercept/siem2cm/issues)
- **Wiki:** [Documentation & FAQs](https://github.com/infopercept/siem2cm/wiki)

---

**© 2015-2020 Infopercept Consulting. All rights reserved.**
