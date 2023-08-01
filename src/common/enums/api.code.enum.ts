/**
 * @description: 定义业务请求状态码
 * @return {*}
 */
export enum ApiCode {
  TIMEOUT = -1, // 系统繁忙
  SUCCESS = 0, // 请求成功

  USER_EXIST = 1000, // 用户已存在
}
