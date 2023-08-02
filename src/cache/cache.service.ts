import { Inject, Injectable } from '@nestjs/common';
import { RedisClientType } from 'redis';
@Injectable()
export class CacheService {
  constructor(@Inject('REDIS_CLIENT') private redisClient: RedisClientType) {}

  /**
   * @description: 获取值
   * @param {*} key
   * @return {*}
   */
  async get(key) {
    let value = await this.redisClient.get(key);
    try {
      value = JSON.parse(value);
    } catch (error) {}
    return value;
  }

  /**
   * @description: 设置值
   * @param {string} key
   * @param {any} value
   * @param {number} second
   * @return {*}
   */
  async set(key: string, value: any, second?: number) {
    value = JSON.stringify(value);
    return await this.redisClient.set(key, value, { EX: second });
  }

  /**
   * @description: 删除值
   * @param {string} key
   * @return {*}
   */
  async del(key: string) {
    return await this.redisClient.del(key);
  }

  /**
   * @description: 清除缓存
   * @return {*}
   */
  async flushall() {
    return await this.redisClient.flushAll();
  }
}
