#pragma once

#include "ast/pass_manager.h"
#include "globalvars.h"

namespace bpftrace::ast {

class NamedParamDefaults : public ast::State<"named_params_defaults"> {
public:
  std::unordered_map<std::string,
                     std::pair<globalvars::GlobalVarValue, std::string>>
      defaults;
};

Pass CreateNamedParamsPass();

} // namespace bpftrace::ast
