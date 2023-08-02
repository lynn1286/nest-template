/**
 * @description: 定义业务请求状态码
 * @return {*}
 */
export enum ErrorCodeEnum {
  /** 请求成功 */
  SUCCESS = 0,
  /** 系统错误 */
  FAIL = 1,
  /** 系统繁忙 */
  TIMEOUT = -1,

  /** 用户已存在 */
  USER_EXIST = 1000,
  /** 请求参数校验失败 */
  QUERY_PARAM_INVALID_FAIL = 1001,
}
