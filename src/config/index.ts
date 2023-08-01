import { registerAs } from '@nestjs/config';
import { readFileSync } from 'fs';
import * as yaml from 'js-yaml';
import { join } from 'path';

const YAML_CONFIG_FILENAME = {
  dev: 'config.dev.yaml',
  prod: 'config.prod.yaml',
  local: 'config.local.yaml',
};

/**
 * @description: 全局配置 - 命名空间 GLOBAL_CONFIG
 */
export default registerAs('GLOBAL_CONFIG', () => {
  const env = process.env.NODE_ENV;

  return yaml.load(
    readFileSync(
      join(
        __dirname,
        env ? YAML_CONFIG_FILENAME[env] : YAML_CONFIG_FILENAME['local'],
      ),
      'utf8',
    ),
  ) as Record<string, any>;
});
