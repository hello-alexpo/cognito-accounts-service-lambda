package com.workingbit.accounts.resource;

import com.workingbit.accounts.common.StringMap;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;

/**
 * Created by Aleksey Popryaduhin on 16:03 17/06/2017.
 */
@Path("/test")
public class EchoController {

    @POST
    @Path("/echo")
    public StringMap echo(StringMap echo) {
        return echo;
    }

    @GET
    @Path("/echo")
    public String echo(@QueryParam("echo") String echo) {
        return echo;
    }
}
