const fp = require('fastify-plugin');
const ip = require('ip');
const jwt = require('jsonwebtoken');
const Ajv = require('ajv-oai');
const parser = require('./lib/parser');

const ajv = new Ajv({
  removeAdditional: true,
  useDefaults: true,
  coerceTypes: true,
});

function isObject(obj) {
  return typeof obj === 'object' && obj !== null;
}

function getObject(data) {
  if (typeof data === 'string') {
    try {
      data = require(data);
    } catch (error) {
      throw new Error(`failed to load ${data}`);
    }
  } else if (typeof data === 'function') {
    data = data();
  }

  return data;
}

// fastify uses the built-in AJV instance during serialization, and that
// instance does not know about int32 and int64 so remove those formats
// from the responses
const unknownFormats = { int32: true, int64: true };

function stripResponseFormats(schema) {
  for (let item in schema) {
    if (isObject(schema[item])) {
      if (schema[item].format && unknownFormats[schema[item].format]) {
        schema[item].format = undefined;
      }
      stripResponseFormats(schema[item]);
    }
  }
}

async function fastifyOpenapiGlue(instance, opts) {
  const service = getObject(opts.service);
  const config = await parser().parse(opts.specification);
  const routeConf = {};

  if (!isObject(service)) {
    throw new Error("'service' parameter must refer to an object");
  }

  instance.setValidatorCompiler(schema => ajv.compile(schema));

  if (config.prefix) {
    routeConf.prefix = config.prefix;
  }

  /**
   * @param request {request}
   * @param entity {string} name of object or field, used for error handling
   * @return {Promise.<void>}
   */
  async function checkJWT(request, entity) {
    const token = request.headers.authorization.split(' ')[1];

    if (!('authorization' in request.headers)) {
      const message = `Missing authorization header for ${entity}`;
      await global.mq.openapiFailures(request, null, message);
      throw new Error(message);
    }

    try {
      const payload = jwt.verify(token, opts.publicKey, { algorithms: ['RS256'] });

      const { IpList, Role } = payload;

      // check that client IP in token range
      if (IpList && IpList.length) {
        const ipInAllowedRange = IpList.some((ipRange) => ip.cidrSubnet(ipRange).contains(request.req.ip));

        if (!ipInAllowedRange) {
          const message = 'IP address if out of range you permit for';

          throw new Error(message);
        }
      }

      request.Roles = Role;
      request.EntityId = payload.EntityId || 'not provided';
      request.EntityType = payload.EntityType || 'not provided';
    } catch (error) {
      const message = `${error.name} ${error.message} for ${entity}`;

      throw new Error(message);
    }
  }

  async function checkAccess(request, item) {
    if (item.schema) {
      const schema = item.schema;
      // TODO extend rule for more x-auth-type
      const xAuthTypes = item.openapiSource['x-AuthType'];
      const even = (element) => element === 'None';

      if (xAuthTypes.length && !xAuthTypes.some(even)) {
        request.xAuthTypes = xAuthTypes;
        await checkJWT(request, schema.operationId);
      }
    }
  }

  async function generateRoutes(routesInstance) {

    config.routes.forEach((item) => {
      try {
        const response = item.schema.response;
        const controllerName = item.operationId;
        const url = item.url.split('/');
        const className = url[1];
        const methodName = url[2];
        const lowerClassName = className.toLowerCase();

        if (response) {
          stripResponseFormats(response);
        }
        let ServiceRouteName;
        if (service[controllerName]) {
          ServiceRouteName = controllerName;

          item.handler = async (request, reply) => service[ServiceRouteName](request, reply);
        } else if (service[lowerClassName] && service[lowerClassName][className + methodName]) {
          ServiceRouteName = className + methodName;

          item.handler = async (request, reply) => service[lowerClassName][ServiceRouteName](request, reply);
        } else {
          throw new Error('Service not exists');
        }

        routesInstance.log.debug('service has', ServiceRouteName);

        item.preValidation = async (request, reply) => {
          if (opts.metrics && opts.metrics[`${ServiceRouteName}${opts.metrics.suffix.total}`]) {
            opts.metrics[`${controllerName}${opts.metrics.suffix.total}`].mark();
          }

          request.controllerName = ServiceRouteName;

          try {
            if (opts.checkToken) await checkAccess(request, item);
          } catch (error) {
            if (error.message.split(' ').includes('expired')) {
              reply.code(440).send({ Status: 440, Description: `${error.message}` });
            } else {
              reply.code(401).send({ Status: 401, Description: `${error.message}` });
            }
          }
        };

      } catch (error) {
        console.error(`Operation ${item.operationId} not implemented`);
        item.handler = async () => {
          throw new Error(`Operation ${item.operationId} not implemented`);
        };
      }

      routesInstance.route(item);
    });
  }

  instance.register(generateRoutes, routeConf);
}

module.exports = fp(fastifyOpenapiGlue, {
  fastify: '>=0.39.0',
  name: 'fastify-openapi-glue',
});
