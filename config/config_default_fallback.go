package config

func (c *DefaultConfig) GetStringDefault(name, defVal string) (configValue string) {
	configValue, found := c.GetString(name)
	if !found {
		configValue = defVal
	}
	return
}

func (c *DefaultConfig) GetIntDefault(name string, defVal int) (configValue int) {
	configValue, found := c.GetInt(name)
	if !found {
		configValue = defVal
	}
	return
}

func (c *DefaultConfig) GetBoolDefault(name string, defVal bool) (configValue bool) {
	configValue, found := c.GetBool(name)
	if !found {
		configValue = defVal
	}
	return
}

func (c *DefaultConfig) GetFloatDefault(name string, defVal float64) (configValue float64) {
	configValue, found := c.GetFloat(name)
	if !found {
		configValue = defVal
	}
	return
}
