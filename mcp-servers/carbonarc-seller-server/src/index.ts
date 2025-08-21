import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { Hono } from "hono";
import { env } from "cloudflare:workers";
// import { McpAccessControl } from "@ory/mcp-access-control";

type Bindings = Env;

const app = new Hono<{
  Bindings: Bindings;
}>();

type State = null;

const accountId = env.ACCOUNT_ID;
const accessKeyId = env.ACCESS_KEY_ID;
const secretAccessKey = env.SECRET_ACCESS_KEY;
const skyfireSellerApiKey = env.SKYFIRE_API_KEY;
const auth0Url = env.AUTH0_URL; 
const auth0GrantType = env.AUTH0_GRANT_TYPE; 
const auth0SubjectTokenType = env.AUTH0_SUBJECT_TOKEN_TYPE; 
const auth0Audience = env.AUTH0_AUDIENCE; 
const auth0ClientId = env.AUTH0_CLIENT_ID;
const auth0ClientSecret = env.AUTH0_CLIENT_SECRET; 
// const oryApiKey = env.ORY_API_KEY;
// const oryProjectId = env.ORY_PROJECT_ID;
const jwksUrl = env.JWKS_URL;
let resToken: string;

// // Initialize Ory access control
// const accessControl = new McpAccessControl({
//   jwksUrl: jwksUrl,
//   issuer: env.JWT_ISSUER,
//   audience: env.CARBONARC_SELLER_ID,
//   claimKey: "bid.skyfireEmail",
//   oryProjectUrl: `https://${oryProjectId}.projects.oryapis.com`,
//   oryApiKey: oryApiKey,
//   schemaId: "preset://email",
// });

// const oryAccessControlTool = accessControl.getToolDefinition();

 const createAccountAndLoginWithAuth0 = async (kyaToken: string, resToken: string) => {
    const auth = await fetch(
            auth0Url,
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify({
                grant_type: auth0GrantType,
                subject_token: kyaToken,
                subject_token_type: auth0SubjectTokenType,
                audience: auth0Audience,
                client_id: auth0ClientId,
                client_secret: auth0ClientSecret
              }),
            }
          );

          const authRes: {
            access_token: string;
            expires_in: number;
            token_type: string;
            issued_token_type: string;
          } = await auth.json();

          // console.log("auth0 auth response", authRes);

          resToken = authRes.access_token;
          console.log("auth0 resToken");
          return {
            content: [
              {
                type: "text",
                text: `Account created. Access token is ${resToken}`,
              },
            ],
          };
 }

// const createAccountAndLoginWithOry = async (
//   kya_token: string,
//   password: string
// ) => {
//   try {
//     const result = await oryAccessControlTool.handler({
//       token: kya_token,
//       password: password,
//     });

//     if (result.success) {
//       return {
//         content: [
//           {
//             type: "text",
//             text: `Authentication successful! accessToken is : ${result.session?.token}`,
//           },
//         ],
//       };
//     } else {
//       return {
//         content: [
//           {
//             type: "text",
//             text: `Authentication failed: ${result.error}`,
//           },
//         ],
//       };
//     }
//   } catch (error) {
//     return {
//       content: [
//         {
//           type: "text",
//           text: `Error: ${error}`,
//         },
//       ],
//     };
//   }
// };

export class MyMCP extends McpAgent<Bindings, State> {
  server = new McpServer({
    name: "carbonarc",
    version: "1.0.0",
    capabilities: {
      resources: {},
      tools: {},
    },
  });

  //   withAuth = (handler: Function) => {
  //     return async function checkSession(params, context) {
  //       // call ORY to validate session 
  //       const validationResult = await accessControl.validateSession(
  //         { "x-session-token": params.access_token },
  //         { headerName: "x-session-token" }
  //       );
        
  //       // Token validation Failure: return error to client 
  //       if (!validationResult.isValid) {
  //         return {
  //           content: [
  //             {
  //               type: "text",
  //               text: `Unauthorized: ${validationResult.error}`,
  //             },
  //           ],
  //         };
  //       }

  //       // Token validation Success: call tool business logic
  //       return handler(params);
  //     };
  // };

  // Initialize mock data
  dataset = {
    id: 1,
    sellerId: 1,
    skyfireReceiverUsername: "CarbonArc",
    data: [
      {
        id: 1,
        dataId: 1,
        title: "US Automobile Data - 2024",
        size: "20MB",
        description: "Data specifically for the year of 2024.",
        price: "0.002",
        sampleDataFormat: {
          type: "csv",
          headers: "Manufacturer,Model,Month,Unit Sales",
        },
        dataUrl:
          "https://pub-303d212fa4df4073b8b38b3de4a72d89.r2.dev/CarbonArc/demo-dataset1.csv",
      },
      {
        id: 2,
        dataId: 2,
        title: "US Automobile Data - 2025",
        size: "10MB",
        description: "Data specifically for the year of 2025.",
        price: "0.001",
        sampleDataFormat: {
          type: "csv",
          headers: "Manufacturer,Model,Month,Unit Sales",
        },
        dataUrl:
          "https://pub-303d212fa4df4073b8b38b3de4a72d89.r2.dev/CarbonArc/demo-dataset2.csv",
      },
    ],
  };

  async init() {
    this.server.tool(
      "create-account-and-login",
      `Having an account with CarbonArc is mandatory to access its tools. This tool creates account for current buyer agent 
      using the KYA token generated by Skyfire and an agent generated new secure regex password that must contain minimum of 8, 
      maximum of 12 alphanumeric characters including atleast 1 uppercase character, 1 numeric character and 1 special character.
      On successful account creation, access token is returned`,
      {
        kya_token: z
          .string()
          .describe(
            "KYA token generated by Skyfire to be used by CarbonArc for account creation"
          ),
        password: z.string().describe(
          `Secure random new regex password generated by agent that contains minimum 8, maximum 12 alphanumeric characters including atleast 
            1 uppercase character, 1 numeric character and 1 special character`
        ),
      },
      async ({ kya_token, password }) => {
        return createAccountAndLoginWithAuth0(kya_token, password);
      }
    );

    this.server.tool(
      "search-dataset",
      `Access token is mandatory to access this tool. This tool returns the list of datasets matching the input prompt. 
      Each dataset has dataset_id which could be further used in other tools`,
      {
        input_prompt: z.string().describe("Input prompt for searching dataset"),
        access_token: z
          .string()
          .describe("Access token required to access and execute this tool"),
      },
      async ({ access_token }) => {
          let response = `Following is the comma separated list of data available from seller ${this.dataset.skyfireReceiverUsername}. 
          Each entry has an id, title and size associated.`;

          for (let i = 0; i < this.dataset.data.length; i++) {
            response =
              response +
              this.dataset.data[i].id +
              ", " +
              this.dataset.data[i].title +
              ", " +
              this.dataset.data[i].size +
              ", " +
              this.dataset.data[i].sampleDataFormat.headers +
              "\n";
          }

          return {
            content: [
              {
                type: "text",
                text: response,
              },
            ],
          };
        
      }
    );

    this.server.tool(
      "get-pricing",
      "Access token is mandatory to access this tool. This tool gets pricing for the dataset_id provided",
      {
        access_token: z
          .string()
          .describe("Access token required to access and execute this tool"),
        dataset_id: z.number().describe("ID for chosen dataset"),
      },
      async ({ access_token, dataset_id }) => {
          const res = this.dataset.data.filter((data) => {
            return data.dataId === dataset_id;
          });

          return {
            content: [
              {
                type: "text",
                text: `Pricing for selected dataset is ${res[0].price}`,
              },
            ],
          };
      }
    );

    this.server.tool(
      "download-dataset",
      `Access token is mandatory to access this tool. Payment should already be executed and JWT PAY token generated by Skyfire is required.
      This tool returns the dataset url for the selected dataset_id`,
      {
        access_token: z
          .string()
          .describe("Access token required to access and execute this tool"),
        dataset_id: z.number().describe("ID for chosen dataset"),
        pay_token: z
          .string()
          .jwt()
          .describe(
            "PAY token (JWT) generated by Skyfire for verifying and claiming payment"
          ),
      },

      async ({ access_token, dataset_id, pay_token }) => {
          const currentDataset = this.dataset.data.filter((data) => {
            return data.dataId === dataset_id;
          });

          const chargeAmount = currentDataset[0].price;

          const response = await fetch(
            `${env.SKYFIRE_API_BASE_URL}/api/v1/tokens/charge`,
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "skyfire-api-key": skyfireSellerApiKey,
              },
              body: JSON.stringify({
                token: pay_token,
                chargeAmount: chargeAmount,
              }),
            }
          );

          const res: {
            amountCharged: string;
            remainingBalance: string;
          } = await response.json();

          if (res.amountCharged === chargeAmount) {
            return {
              content: [
                {
                  type: "text",
                  text: `Purchased dataset ${dataset_id}. Download from ${currentDataset[0].dataUrl}`,
                },
              ],
            };
          }

          return {
            content: [
              {
                type: "text",
                text: `Unable to complete transaction. Contact us for more details.`,
              },
            ],
          };
      }
    );
  }
}

// Render a basic homepage placeholder to make sure the app is up
app.get("/", async (c) => {
  return c.html("Home Page for CarbonArc Seller MCP Server");
});

app.mount("/", (req, env, ctx) => {
  return MyMCP.mount("/sse").fetch(req, env, ctx);
});

export default app;