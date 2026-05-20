function buildUserQuery(user) {
  switch (user.role) {
    case "global-admin":
      return {};

    case "local-admin":
      return {
        companyName: user.companyName,
        role: { $in: ["employee", "local-admin"] }
      };

    case "employee":
      return {
        _id: user.id
      };

    default:
      return {};
  }
}

function buildLogQuery(user) {
  switch (user.role) {
    case "global-admin":
      return {};

    case "local-admin":
      return {
        company: user.companyName
      };

    case "employee":
      return {
        userId: user.id
      };

    default:
      return {};
  }
}

module.exports = {
  buildUserQuery,
  buildLogQuery
};