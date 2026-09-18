#ifndef  CRAILS_SECURE_COMPARE_HPP
# define CRAILS_SECURE_COMPARE_HPP

# include <string_view>

namespace Crails
{
  bool secure_compare(const std::string_view a, const std::string_view b);
}

#endif
