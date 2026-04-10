module.exports = (prompt, vars, context) => {
  return {
    prompt,
    preload_list: vars.preload_list !== false,
    max_list: vars.max_list || 10,
    direct_tool: vars.direct_tool || null,
  };
};
