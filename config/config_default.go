package config

import "strings"

type DefaultConfig struct {
	configData map[string]interface{}
}

func (c *DefaultConfig) get(name string) (result interface{}, found bool) {
	data := c.configData

	for _, key := range strings.Split(name, ":") {
		result, found = data[key]
		if newSection, ok := result.(map[string]interface{}); ok && found {
			data = newSection
		} else {
			return
		}
	}
	return
}

func (c *DefaultConfig) GetSection(sectionName string) (section Configuration, found bool) {
	value, found := c.get(sectionName)
	if found {
		if sectionData, ok := value.(map[string]interface{}); ok {
			section = &DefaultConfig{sectionData}
		}
	}
	return
}

func (c *DefaultConfig) GetString(name string) (configValue string, found bool) {
	value, found := c.get(name)
	if found {
		configValue = value.(string)
	}
	return
}

func (c *DefaultConfig) GetInt(name string) (configValue int, found bool) {
	value, found := c.get(name)
	if found {
		configValue = int(value.(float64))
	}
	return
}

func (c *DefaultConfig) GetBool(name string) (configValue, found bool) {
	value, found := c.get(name)
	if found {
		configValue = value.(bool)
	}
	return
}

func (c *DefaultConfig) GetFloat(name string) (configValue float64, found bool) {
	value, found := c.get(name)
	if found {
		configValue = value.(float64)
	}
	return
}
