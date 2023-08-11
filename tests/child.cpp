#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "child.h"
#include "childhelper.h"
#include "utils.h"

namespace bpftrace {
namespace test {
namespace child {

using ::testing::HasSubstr;

#define TEST_BIN "/bin/ls"
#define TEST_BIN_ERR "/bin/ls /does/not/exist/abc"
#define TEST_BIN_SLOW "/bin/sleep 10"

TEST(childproc, exe_does_not_exist)
{
  try
  {
    ChildProc child("/does/not/exist/abc/fed");
    FAIL();
  }
  catch (const std::runtime_error &e)
  {
    EXPECT_THAT(e.what(), HasSubstr("does not exist or is not executable"));
  }
}

TEST(childproc, too_many_arguments)
{
  std::stringstream cmd;
  cmd << "/bin/ls";
  for (int i = 0; i < 280; i++)
    cmd << " a";

  try
  {
    ChildProc child(cmd.str());
    FAIL();
  }
  catch (const std::runtime_error &e)
  {
    EXPECT_THAT(e.what(), HasSubstr("Too many arguments"));
  }
}

TEST(childproc, child_exit_success)
{
  // Spawn a child that exits successfully
  auto child = getChild(TEST_BIN);

  child->run();
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_EQ(child->exit_code(), 0);
  EXPECT_EQ(child->term_signal(), -1);
}

TEST(childproc, child_exit_err)
{
  // Spawn a child that exits with an error
  auto child = getChild(TEST_BIN_ERR);

  child->run();
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_TRUE(child->exit_code() > 0);
  EXPECT_EQ(child->term_signal(), -1);
}

TEST(childproc, terminate)
{
  auto child = getChild(TEST_BIN_SLOW);

  child->run();
  child->terminate();
  wait_for(child.get(), 100);
  EXPECT_FALSE(child->is_alive());
  EXPECT_EQ(child->term_signal(), SIGTERM);
}

TEST(childproc, destructor_destroy_child)
{
  pid_t child_pid = 0;
  {
    std::unique_ptr<ChildProc> child = getChild(TEST_BIN_SLOW);
    child->run();
    child_pid = child->pid();
    // Give child a little bit of time to execve before we kill it
    msleep(25);
  }

  int status = 0;
  pid_t ret = waitpid(child_pid, &status, WNOHANG);
  if (ret == -1 && errno == ECHILD)
    return;

  FAIL() << "Child should've been killed but appears to be alive: ret: " << ret
         << ", errno: " << errno << ", status: " << status << std::endl;
}

TEST(childproc, child_kill_before_exec)
{
  signal(SIGHUP, SIG_DFL);
  auto child = getChild(TEST_BIN_SLOW);

  EXPECT_EQ(kill(child->pid(), SIGHUP), 0);
  wait_for(child.get(), 100);

  EXPECT_FALSE(child->is_alive());
  EXPECT_EQ(child->exit_code(), -1);
  EXPECT_EQ(child->term_signal(), SIGHUP);
}

TEST(childproc, stop_cont)
{
  // STOP/CONT should not incorrectly mark the child
  // as dead
  auto child = getChild(TEST_BIN_SLOW);
  int status = 0;

  child->run();
  msleep(25);
  EXPECT_TRUE(child->is_alive());

  if (kill(child->pid(), SIGSTOP))
    FAIL() << "kill(SIGSTOP)";

  waitpid(child->pid(), &status, WUNTRACED);
  if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP))
    FAIL() << "! WIFSTOPPED";

  EXPECT_TRUE(child->is_alive());

  if (kill(child->pid(), SIGCONT))
    FAIL() << "kill(SIGCONT)";

  waitpid(child->pid(), &status, WCONTINUED);
  if (!WIFCONTINUED(status))
    FAIL() << "! WIFCONTINUED";

  EXPECT_TRUE(child->is_alive());

  child->terminate();
  wait_for(child.get(), 100);
  EXPECT_EQ(child->exit_code(), -1);
  EXPECT_EQ(child->term_signal(), SIGTERM);
}

TEST(childproc, ptrace_child_exit_success)
{
  auto child = getChild(TEST_BIN);

  child->run(true);
  child->resume();
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_EQ(child->exit_code(), 0);
  EXPECT_EQ(child->term_signal(), -1);
}

TEST(childproc, ptrace_child_exit_error)
{
  auto child = getChild(TEST_BIN_ERR);

  child->run(true);
  child->resume();
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_TRUE(child->exit_code() > 0);
  EXPECT_EQ(child->term_signal(), -1);
}

TEST(childproc, ptrace_child_kill_before_execve)
{
  auto child = getChild(TEST_BIN);

  child->run(true);
  child->terminate(true);
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_EQ(child->exit_code(), -1);
  EXPECT_EQ(child->term_signal(), 9);
}

TEST(childproc, ptrace_child_term_before_execve)
{
  auto child = getChild(TEST_BIN);

  child->run(true);
  child->terminate();
  wait_for(child.get(), 1000);
  EXPECT_FALSE(child->is_alive());
  EXPECT_EQ(child->exit_code(), -1);
  EXPECT_EQ(child->term_signal(), 15);
}

TEST(childproc, multi_exec_match)
{
  std::string tmpdir = "/tmp/bpftrace-test-child-XXXXXX";

  // Create directory for test
  if (::mkdtemp(&tmpdir[0]) == nullptr)
  {
    throw std::runtime_error("creating temporary path for tests failed");
  }

  const std_filesystem::path path(tmpdir);
  const std_filesystem::path usr = path / "usr";
  const std_filesystem::path usr_bin = usr / "bin";
  const std_filesystem::path symlnk_bin = path / "bin";
  const std_filesystem::path binary = usr_bin / "mysleep";

  if (!std_filesystem::create_directory(usr))
  {
    throw std::runtime_error("creating subdirectory for tests failed");
  }
  if (!std_filesystem::create_directory(usr_bin))
  {
    throw std::runtime_error("creating subdirectory for tests failed");
  }

  // Create symbol link: bin -> usr/bin
  char cwd[512];
  if (::getcwd(cwd, sizeof(cwd)) == NULL)
  {
    throw std::runtime_error("Failed to getcwd().");
  }
  if (::chdir(path.c_str()))
  {
    throw std::runtime_error("Failed to chdir().");
  }
  std_filesystem::create_directory_symlink("usr/bin", "bin");
  if (::chdir(cwd))
  {
    throw std::runtime_error("Failed to chdir().");
  }

  // Copy a 'mysleep' binary and add x permission
  {
    std::ifstream src;
    std::ofstream dst;

    src.open("/bin/sleep", std::ios::in | std::ios::binary);
    dst.open(binary, std::ios::out | std::ios::binary);
    dst << src.rdbuf();
    src.close();
    dst.close();
    int err = chmod(binary.c_str(), 0755);
    if (err)
      throw std::runtime_error("Failed to chmod dwarf data file: " +
                               std::to_string(err));
  }

  // Set ENV
  char ENV_PATH[2048];
  char *env = ::getenv("PATH");
  snprintf(ENV_PATH,
           sizeof(ENV_PATH),
           "PATH=%s:%s:%s",
           env,
           usr_bin.c_str(),
           symlnk_bin.c_str());

  ::putenv(ENV_PATH);

  // 'mysleep' will match /bin/mysleep and /usr/bin/mysleep, but they are
  // actually the same file.
  auto child = getChild("mysleep 5");

  child->run();
  child->terminate();
  wait_for(child.get(), 100);
  EXPECT_FALSE(child->is_alive());
  EXPECT_EQ(child->term_signal(), SIGTERM);
}

} // namespace child
} // namespace test
} // namespace bpftrace
