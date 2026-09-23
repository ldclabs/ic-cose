import { Actor, HttpAgent } from "@icp-sdk/core/agent";

// A supplied agent owns its identity, root key and verification policy.
// For a local replica, explicitly await agent.fetchRootKey() before calling here.
export const createActorWithInterface = (canisterId, idlFactory, options = {}) => {
  const agent = options.agent || new HttpAgent({ ...options.agentOptions });
  return Actor.createActor(idlFactory, {
    agent,
    canisterId,
    ...options.actorOptions,
  });
};
