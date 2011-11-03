package com.atlassian.bamboo.plugins.git;

import org.apache.commons.lang.StringUtils;
import org.codehaus.plexus.util.IOUtil;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Helper class that executes a native command and properly handles the output and error streams in
 * separate threads to avoid a deadlock while executing the external command.
 *
 * @author ssaasen@atlassian.com
 */
class ProcessExecution
{
    static interface ExecutionResult<O>
    {
        O getOutput() throws InterruptedException;

        List<String> getErrors();

        int returnCodes();
    }

    interface StreamConverter<T>
    {
        T convert(InputStream is) throws IOException;
    }

    static class ListStreamConverter implements StreamConverter<List<String>>
    {
        public List<String> convert(InputStream is) throws IOException
        {
            final List<String> result = new ArrayList<String>();
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            String line;
            while ((line = br.readLine()) != null)
            {
                result.add(line);
            }
            return result;
        }
    }

    static class FileStreamConverter implements StreamConverter<File>
    {
        private final File path;

        FileStreamConverter(File parent, String name)
        {
            this.path = new File(parent, name);
        }

        public File convert(InputStream is) throws IOException
        {
            OutputStream out = new FileOutputStream(path);
            try
            {
                IOUtil.copy(is, out);
            }
            finally
            {
                out.close();
            }
            return path;
        }
    }


    <O> ExecutionResult<O> executeCommand(String[] cmd, StreamConverter<O> outputConverter) throws IOException, InterruptedException
    {
        return executeCommand(Arrays.asList(cmd), outputConverter);

    }

    <O> ExecutionResult<O> executeCommand(List<String> cmd, StreamConverter<O> outputConverter) throws IOException, InterruptedException
    {
        final Process p = new ProcessBuilder(cmd).start();
        final ExecutorService s = Executors.newFixedThreadPool(2);
        final Future<O> output = s.submit(new StreamSink<O>(p.getInputStream(), outputConverter));
        Future<List<String>> error = s.submit(new StreamSink<List<String>>(p.getErrorStream(), new ListStreamConverter()));
        try
        {
            final int ret = p.waitFor();
            final List<String> errors = error.get(1, TimeUnit.SECONDS);
            if (ret != 0)
            {
                throw new RuntimeException("Command execution failed with: " + StringUtils.join(errors, '\n'));
            }
            return new ExecutionResult<O>()
            {
                public O getOutput() throws InterruptedException
                {
                    try
                    {
                        return output.get(1, TimeUnit.SECONDS);
                    }
                    catch (ExecutionException e)
                    {
                        throw new RuntimeException("Command execution failed with " + e.getLocalizedMessage(), e);
                    }
                    catch (TimeoutException e)
                    {
                        throw new RuntimeException("Command execution timed out with " + e.getLocalizedMessage(), e);
                    }
                }

                public List<String> getErrors()
                {
                    return errors;
                }

                public int returnCodes()
                {
                    return ret;
                }
            };
        }
        catch (ExecutionException e)
        {
            throw new RuntimeException("Command execution failed with: " + e.getLocalizedMessage(), e);
        }
        catch (TimeoutException e)
        {
            throw new RuntimeException("Command execution timed out: " + e.getLocalizedMessage(), e);
        }
        finally
        {
            s.shutdownNow();
        }
    }

    /**
     * Callable that will consume *and* close a given InputStream and returns a List of Strings read off of the stream.
     */
    private static class StreamSink<T> implements Callable<T>
    {
        private final InputStream is;
        private final StreamConverter<T> converter;

        StreamSink(InputStream is, StreamConverter<T> converter)
        {
            this.is = is;
            this.converter = converter;
        }

        public T call() throws Exception
        {
            try
            {
                return converter.convert(is);
            }
            finally
            {
                IOUtil.close(is);
            }
        }
    }
}

