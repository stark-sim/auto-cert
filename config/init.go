package config

import (
	"errors"
	"github.com/fsnotify/fsnotify"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
)

const DefaultConfigPath = "./config.yaml"

// LegoConfig 组件需要的配置
type LegoConfig struct {
	Email   string   `mapstructure:"email"`
	Domains []string `mapstructure:"domains"`

	// 自定义私钥存放路径，若留空为 lego 默认路径
	PrivateKeyPath string `mapstructure:"private_key_path"`
}

// AliyunConfig 阿里云服务提供方的配置，一般要从环境变量中获取
type AliyunConfig struct {
	// 由于 aliyun 的主账户的 key 如果太久不用会自动禁用，所以最好用 RAM 用户相关的配置
	AccessKey string `mapstructure:"access_key"`
	SecretKey string `mapstructure:"secret_key"`
}

// GlobalConfig 全局的配置信息
type GlobalConfig struct {
	Lego   LegoConfig   `mapstructure:"lego"`
	Aliyun AliyunConfig `mapstructure:"aliyun"`
}

// Config 全局变量供其他地方使用
var Config GlobalConfig

// 配置优先级别：真环境变量 (export) > .env 文件 > config.yaml
func init() {
	// 初始化配置文件路径
	viper.SetConfigFile(DefaultConfigPath)

	// 观察配置文件变动，比如多加个域名
	viper.WatchConfig()
	viper.OnConfigChange(func(in fsnotify.Event) {
		logrus.Infof("config file has changed")
		if err := viper.Unmarshal(&Config); err != nil {
			logrus.Errorf("unmarshal config file err: %v", err)
			panic(err)
		}
	})

	// 将配置文件读入 viper
	if err := viper.ReadInConfig(); err != nil {
		logrus.Errorf("read config file err: %v", err)
		panic(err)
	}

	// 使用环境变量前，把 .env 也加载到环境变量中，注意 .env 文件的优先级比真环境变量低，不会覆盖
	if err := godotenv.Load(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// 如果只是没有这个文件，不直接报错，毕竟可以有真的环境变量
			logrus.Warn("no .env file found")
		} else {
			logrus.Errorf("load env file err: %v", err)
			panic(err)
		}
	}

	// 还有从环境变量中获取
	viper.AutomaticEnv()

	// 绑定对应的环境变量到配置变量
	var err error
	err = viper.BindEnv("aliyun.access_key", "ALIYUN_ACCESS_KEY")
	err = viper.BindEnv("aliyun.secret_key", "ALIYUN_SECRET_KEY")
	if err != nil {
		logrus.Errorf("bind aliyun env err: %v", err)
		panic(err)
	}

	// viper 中的数据解析到变量中
	if err := viper.Unmarshal(&Config); err != nil {
		logrus.Errorf("unmarshal config file err: %v", err)
		panic(err)
	}
}
